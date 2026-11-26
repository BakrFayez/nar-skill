"""Animation-system parsers (Part 4, section 4.2).

Structural decoders for the animation formats a shipped
Android target can carry, stdlib only. Detection is by
STRUCTURE, not just extension: a random ``.json`` is not
Lottie, Spine or Creature unless the document shape says
so, and binary formats must pass their magic/header guards
before any count is emitted.

Public surface:

- :func:`classify_and_parse` — one member (name + bytes)
  to one record or None. A record is
  ``{system, file, source_split, status, facts, reason,
  probe}`` with status ``decoded`` (structure parsed,
  counts are real) or ``identified_only`` (the format is
  identified but this rung does not decode it — reason and
  probe always say why and what would).
- :func:`scan_target` — the whole-target report behind
  ``nar-anim.py``: resolves the target through
  :mod:`narlib.container`, scans the resolved archive
  roots' members (bounded reads, 32 MiB per member),
  builds composition records for skeletal (Spine /
  DragonBones) and physics-driven rigs, and detects
  physics symbol clusters in ``lib/**/*.so`` members.
- Malformed members degrade to per-file ``identified_only``
  records with a reason, never a crash.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import json
import os
import plistlib
import re
import struct
import xml.etree.ElementTree as ET
import zipfile

from . import container as _container
from .elf import Elf, ElfError, SHT_DYNSYM

VERSION = "3.0.1"

#: Per-member read cap for the target scan (bounded reads).
MAX_MEMBER_BYTES = 32 * 1024 * 1024

SYSTEMS = ("spine", "dragonbones", "lottie", "rive",
           "aseprite", "unity-animator",
           "godot-animationplayer", "spriter", "creature",
           "cocos-ccb", "gif", "pag", "android-view")


def _record(system, name, source_split, status, facts,
            reason=None, probe=None):
    return {"system": system, "file": name,
            "source_split": source_split, "status": status,
            "facts": facts or {}, "reason": reason,
            "probe": probe}


def _identified(system, name, source_split, facts, reason,
                probe):
    return _record(system, name, source_split,
                   "identified_only", facts, reason, probe)


# ------------------------------------------------------------------
# Shared small readers
# ------------------------------------------------------------------
def _read_varint(data, off):
    """Unsigned LEB128 varint at ``off`` -> (value, new_off).

    Raises ValueError on truncation or an overlong encoding
    (callers treat that as an inconsistent parse)."""
    result = 0
    shift = 0
    for _ in range(10):
        if off >= len(data):
            raise ValueError("varint runs past end of data")
        byte = data[off]
        off += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, off
        shift += 7
    raise ValueError("varint longer than 10 bytes")


def _is_number(value):
    return isinstance(value, (int, float)) \
        and not isinstance(value, bool)


# ------------------------------------------------------------------
# 1. Spine
# ------------------------------------------------------------------
def is_spine_json(obj):
    """Structural Spine check: a dict carrying the skeleton
    sections (bones plus at least one of slots/skins/
    animations), with bones a list of dicts."""
    if not isinstance(obj, dict):
        return False
    bones = obj.get("bones")
    if not isinstance(bones, list) or not bones:
        return False
    if not all(isinstance(b, dict) for b in bones):
        return False
    return any(isinstance(obj.get(k), (list, dict))
               for k in ("slots", "skins", "animations"))


def _spine_max_bone_time(node, depth=0):
    """Largest numeric ``time`` in a bone-timeline subtree."""
    best = None
    if depth > 12:
        return best
    if isinstance(node, dict):
        t = node.get("time")
        if _is_number(t):
            best = float(t)
        for value in node.values():
            sub = _spine_max_bone_time(value, depth + 1)
            if sub is not None and (best is None or sub > best):
                best = sub
    elif isinstance(node, list):
        for item in node:
            sub = _spine_max_bone_time(item, depth + 1)
            if sub is not None and (best is None or sub > best):
                best = sub
    return best


def parse_spine_json(obj, name, source_split=None):
    bones = obj.get("bones") or []
    slots = obj.get("slots") or []
    if not isinstance(slots, list):
        slots = []
    skins_raw = obj.get("skins")
    skin_names = []
    if isinstance(skins_raw, list):
        skin_names = [str(s.get("name")) for s in skins_raw
                      if isinstance(s, dict) and s.get("name")]
    elif isinstance(skins_raw, dict):
        skin_names = [str(k) for k in skins_raw]
    skeleton = obj.get("skeleton") or {}
    if not isinstance(skeleton, dict):
        skeleton = {}
    events_raw = obj.get("events")
    if isinstance(events_raw, dict):
        event_names = sorted(str(k) for k in events_raw)
    elif isinstance(events_raw, list):
        event_names = [str(e.get("name")) for e in events_raw
                       if isinstance(e, dict) and e.get("name")]
    else:
        event_names = []
    animations = {}
    anims_raw = obj.get("animations")
    items = []
    if isinstance(anims_raw, dict):
        items = list(anims_raw.items())
    elif isinstance(anims_raw, list):
        items = [(a.get("name"), a) for a in anims_raw
                 if isinstance(a, dict)]
    for anim_name, anim in items:
        if not isinstance(anim, dict) or anim_name is None:
            continue
        duration = _spine_max_bone_time(anim.get("bones"))
        animations[str(anim_name)] = {
            "timeline_groups": sorted(str(k) for k in anim),
            "duration_estimate": duration,
            "duration_basis": "max keyframe time found in "
                              "bone timelines (estimate)",
        }
    facts = {
        "skeleton_hash": skeleton.get("hash"),
        "version": skeleton.get("spine"),
        "bones_count": len(bones),
        "bone_names_sample": [str(b.get("name"))
                              for b in bones[:10]
                              if isinstance(b, dict)
                              and b.get("name")],
        "slots_count": len(slots),
        "slot_names_sample": [str(s.get("name"))
                              for s in slots[:10]
                              if isinstance(s, dict)
                              and s.get("name")],
        "slots_detail": [
            {"name": str(s.get("name")),
             "bone": s.get("bone")}
            for s in slots if isinstance(s, dict)
            and s.get("name")],
        "skins_count": len(skin_names),
        "skin_names": skin_names,
        "ik_constraints_count": len(obj.get("ik") or []),
        "transform_constraints_count": len(
            obj.get("transform") or []),
        "path_constraints_count": len(obj.get("path") or []),
        "events": event_names,
        "animations": animations,
        "animation_count": len(animations),
    }
    return _record("spine", name, source_split, "decoded",
                   facts)


def _spine_binary_string(data, off):
    """Spine binary string: varint byte-count (count
    includes one terminator slot: 0 = null, 1 = empty,
    n = n-1 UTF-8 bytes). Guarded; raises ValueError."""
    count, off = _read_varint(data, off)
    if count == 0:
        return None, off
    if count == 1:
        return "", off
    n = count - 1
    if off + n > len(data):
        raise ValueError("string runs past end of data")
    return data[off:off + n].decode("utf-8"), off + n


def parse_spine_skel(data, name, source_split=None):
    """Spine .skel header-only parse: hash + version strings
    then the skeleton floats, emitted ONLY when every
    guarded read stays consistent."""
    reason = ("binary timeline decode is version-sensitive; "
              "JSON export decodes fully")
    probe = ("Export the skeleton as Spine JSON from the "
             "Spine editor for full timeline decode, or add "
             "a version-pinned .skel timeline decoder.")
    try:
        skeleton_hash, off = _spine_binary_string(data, 0)
        version, off = _spine_binary_string(data, off)
    except (ValueError, UnicodeDecodeError) as exc:
        return _identified(
            "spine", name, source_split, {},
            f"Spine binary header strings do not parse "
            f"consistently ({exc}); identified by extension "
            f"only. {reason}", probe)
    facts = {"version": version}
    if skeleton_hash:
        facts["skeleton_hash"] = skeleton_hash
    # After the two strings come x, y, width, height as
    # big-endian floats (the documented 3.8+/4.x layout).
    if off + 16 <= len(data):
        try:
            x, y, width, height = struct.unpack_from(
                ">ffff", data, off)
        except struct.error:
            x = None
        if x is not None and all(
                v == v and abs(v) != float("inf")
                for v in (x, y, width, height)) \
                and width >= 0 and height >= 0 \
                and abs(width) < 1e7 and abs(height) < 1e7:
            facts.update({"x": x, "y": y, "width": width,
                          "height": height})
    return _identified("spine", name, source_split, facts,
                       reason, probe)


# ------------------------------------------------------------------
# 2. DragonBones
# ------------------------------------------------------------------
def _is_dragonbones_ske(obj):
    if not isinstance(obj, dict):
        return False
    armature = obj.get("armature")
    return isinstance(armature, list) and bool(armature) \
        and all(isinstance(a, dict) and
                isinstance(a.get("bone"), list)
                for a in armature)


def _is_dragonbones_tex(obj):
    return isinstance(obj, dict) \
        and isinstance(obj.get("SubTexture"), list) \
        and "imagePath" in obj


def parse_dragonbones_ske(obj, name, source_split=None):
    armatures = []
    for arm in obj.get("armature") or []:
        if not isinstance(arm, dict):
            continue
        animations = []
        for anim in arm.get("animation") or []:
            if isinstance(anim, dict):
                animations.append({
                    "name": anim.get("name"),
                    "duration": anim.get("duration"),
                    "play_times": anim.get("playTimes")})
        slots = arm.get("slot") or []
        armatures.append({
            "name": arm.get("name"),
            "bones_count": len(arm.get("bone") or []),
            "slots_count": len(slots),
            "skins_count": len(arm.get("skin") or []),
            "ik_count": len(arm.get("ik") or []),
            "animations": animations,
            "animation_count": len(animations),
            "slots_detail": [
                {"name": str(s.get("name")),
                 "parent": s.get("parent")}
                for s in slots if isinstance(s, dict)
                and s.get("name")],
        })
    facts = {"frame_rate": obj.get("frameRate"),
             "version": obj.get("version"),
             "armatures": armatures,
             "armature_count": len(armatures),
             "bones_count": sum(a["bones_count"]
                                for a in armatures),
             "slots_count": sum(a["slots_count"]
                                for a in armatures),
             "animation_count": sum(a["animation_count"]
                                    for a in armatures)}
    return _record("dragonbones", name, source_split,
                   "decoded", facts)


def parse_dragonbones_tex(obj, name, source_split=None):
    subs = obj.get("SubTexture") or []
    facts = {"image_path": obj.get("imagePath"),
             "width": obj.get("width"),
             "height": obj.get("height"),
             "frame_count": len(subs),
             "frame_names_sample": [
                 str(s.get("name")) for s in subs[:10]
                 if isinstance(s, dict) and s.get("name")]}
    return _record("dragonbones", name, source_split,
                   "decoded", facts)


# ------------------------------------------------------------------
# 3. Lottie
# ------------------------------------------------------------------
def is_lottie(obj):
    """Structural Lottie check: ``v`` + ``fr`` + a layers
    list whose entries carry the ``ty`` layer-type field."""
    if not isinstance(obj, dict):
        return False
    if "v" not in obj or "fr" not in obj:
        return False
    layers = obj.get("layers")
    if not isinstance(layers, list) or not layers:
        return False
    return any(isinstance(layer, dict) and "ty" in layer
               for layer in layers)


def _lottie_shape_count(node, depth=0):
    count = 0
    if depth > 40:
        return count
    if isinstance(node, dict):
        if "ty" in node:
            count += 1
        for value in node.values():
            count += _lottie_shape_count(value, depth + 1)
    elif isinstance(node, list):
        for item in node:
            count += _lottie_shape_count(item, depth + 1)
    return count


def _lottie_keyframed_count(node, depth=0):
    count = 0
    if depth > 60:
        return count
    if isinstance(node, dict):
        keys = node.get("k")
        if node.get("a") == 1 and isinstance(keys, list) \
                and any(isinstance(kf, dict) and "t" in kf
                        for kf in keys):
            count += 1
        for value in node.values():
            count += _lottie_keyframed_count(value, depth + 1)
    elif isinstance(node, list):
        for item in node:
            count += _lottie_keyframed_count(item, depth + 1)
    return count


def parse_lottie(obj, name, source_split=None):
    layers = obj.get("layers") or []
    type_counts = {}
    for layer in layers:
        if isinstance(layer, dict):
            key = str(layer.get("ty"))
            type_counts[key] = type_counts.get(key, 0) + 1
    assets = obj.get("assets") or []
    precomps = [a for a in assets if isinstance(a, dict)
                and isinstance(a.get("layers"), list)]
    shapes = 0
    for layer in layers:
        if isinstance(layer, dict) \
                and isinstance(layer.get("shapes"), list):
            shapes += _lottie_shape_count(layer["shapes"])
    fr = obj.get("fr")
    ip = obj.get("ip")
    op = obj.get("op")
    duration = None
    if _is_number(fr) and fr and _is_number(ip) \
            and _is_number(op):
        duration = round((op - ip) / fr, 3)
    facts = {
        "version": obj.get("v"),
        "name": obj.get("nm"),
        "frame_rate": fr,
        "in_point": ip,
        "out_point": op,
        "duration_s": duration,
        "width": obj.get("w"),
        "height": obj.get("h"),
        "layers_count": len(layers),
        "layer_type_counts": type_counts,
        "layer_names_sample": [
            str(layer.get("nm")) for layer in layers[:10]
            if isinstance(layer, dict) and layer.get("nm")],
        "precomp_count": len(precomps),
        "precomp_ids": [str(a.get("id")) for a in precomps
                        if a.get("id") is not None],
        "shapes_count": shapes,
        "keyframed_properties_count":
            _lottie_keyframed_count(obj),
        "keyframed_properties_basis":
            "counted properties with a==1 whose k is a "
            "keyframe list containing t (approximate)",
    }
    return _record("lottie", name, source_split, "decoded",
                   facts)


# ------------------------------------------------------------------
# 10. Creature (checked with the other JSON shapes)
# ------------------------------------------------------------------
def is_creature(obj):
    return isinstance(obj, dict) \
        and isinstance(obj.get("mesh"), dict) \
        and isinstance(obj.get("animation"), dict)


def parse_creature(obj, name, source_split=None):
    mesh = obj.get("mesh") or {}
    points = mesh.get("points")
    regions = mesh.get("regions")
    animations = {}
    for anim_name, anim in (obj.get("animation") or {}).items():
        length = None
        if isinstance(anim, dict):
            if _is_number(anim.get("length")):
                length = anim.get("length")
            elif _is_number(anim.get("start_time")) \
                    and _is_number(anim.get("end_time")):
                length = anim["end_time"] - anim["start_time"]
        animations[str(anim_name)] = {"length": length}
    facts = {
        "mesh_points_count": len(points)
        if isinstance(points, list) else 0,
        "mesh_regions_count": len(regions)
        if isinstance(regions, list) else 0,
        "mesh_region_names_sample": [
            str(r.get("name")) for r in regions[:10]
            if isinstance(regions, list)
            and isinstance(r, dict) and r.get("name")],
        "animations": animations,
        "animation_count": len(animations),
    }
    return _record("creature", name, source_split, "decoded",
                   facts)


# ------------------------------------------------------------------
# 4. Aseprite (.ase/.aseprite binary)
# ------------------------------------------------------------------
ASE_MAGIC = 0xA5E0
ASE_FRAME_MAGIC = 0xF1FA


def _ase_string(data, off, end):
    """Aseprite STRING: uint16 length + UTF-8 bytes."""
    if off + 2 > end:
        raise ValueError("truncated string length")
    n = struct.unpack_from("<H", data, off)[0]
    off += 2
    if off + n > end:
        raise ValueError("truncated string body")
    return data[off:off + n].decode("utf-8", "replace"), off + n


def parse_aseprite(data, name, source_split=None):
    probe = ("Re-export from Aseprite as JSON metadata, or "
             "extend the chunk walk for the failing chunk "
             "type.")
    if len(data) < 128:
        return _identified(
            "aseprite", name, source_split, {},
            f"file is {len(data)} bytes, shorter than the "
            f"128-byte Aseprite header; identified by "
            f"extension only", probe)
    file_size, magic, frames_declared, width, height, \
        color_depth = struct.unpack_from("<IHHHHH", data, 0)
    flags = struct.unpack_from("<I", data, 14)[0]
    header = {"file_size_header": file_size,
              "frames_declared": frames_declared,
              "width": width, "height": height,
              "color_depth": color_depth, "flags": flags}
    if magic != ASE_MAGIC:
        return _identified(
            "aseprite", name, source_split, header,
            f"bad header magic {magic:#06x} (expected "
            f"{ASE_MAGIC:#06x}); not decoded", probe)
    layers = []
    cels = 0
    tags = []
    slices = []
    palette_chunks = 0
    userdata_chunks = 0
    chunk_types = {}
    off = 128
    try:
        for _frame in range(frames_declared):
            if off + 16 > len(data):
                raise ValueError("truncated frame header")
            frame_bytes, frame_magic, old_count = \
                struct.unpack_from("<IHH", data, off)
            duration = struct.unpack_from("<H", data,
                                          off + 8)[0]
            _ = duration  # frame duration is not reported
            new_count = struct.unpack_from("<I", data,
                                           off + 12)[0]
            if frame_magic != ASE_FRAME_MAGIC:
                raise ValueError(
                    f"bad frame magic {frame_magic:#06x}")
            if frame_bytes < 16 or off + frame_bytes > len(data):
                raise ValueError("frame size out of bounds")
            chunk_count = new_count if old_count == 0xFFFF \
                else old_count
            frame_end = off + frame_bytes
            coff = off + 16
            for _chunk in range(chunk_count):
                if coff + 6 > frame_end:
                    raise ValueError("truncated chunk header")
                chunk_size, chunk_type = struct.unpack_from(
                    "<IH", data, coff)
                if chunk_size < 6 or coff + chunk_size > frame_end:
                    raise ValueError("chunk size out of bounds")
                chunk_types[f"{chunk_type:#06x}"] = \
                    chunk_types.get(f"{chunk_type:#06x}", 0) + 1
                body = coff + 6
                cend = coff + chunk_size
                if chunk_type == 0x2004:  # layer
                    if body + 16 <= cend:
                        lname, _ = _ase_string(
                            data, body + 16, cend)
                        if lname not in layers:
                            layers.append(lname)
                elif chunk_type == 0x2005:  # cel
                    cels += 1
                elif chunk_type == 0x2018:  # tags
                    if body + 2 <= cend:
                        tag_count = struct.unpack_from(
                            "<H", data, body)[0]
                        toff = body + 2 + 8
                        for _t in range(tag_count):
                            # from,to,dir,repeat,res6,
                            # colour3,extra = 17 bytes, then
                            # the tag name string.
                            tname, toff = _ase_string(
                                data, toff + 17, cend)
                            tags.append(tname)
                elif chunk_type == 0x2022:  # slices
                    if body + 8 <= cend:
                        # DWORD count, DWORD flags (bit 1:
                        # every slice carries 9-patch data,
                        # bit 2: every slice carries a
                        # pivot), then per slice: name
                        # string, frame, x, y, w, h.
                        slice_count, sflags = \
                            struct.unpack_from("<II", data,
                                               body)
                        soff = body + 8
                        for _s in range(slice_count):
                            sname, soff = _ase_string(
                                data, soff, cend)
                            slices.append(sname)
                            soff += 20  # frame, x, y, w, h
                            if sflags & 1:
                                soff += 16  # 9-patch centre
                            if sflags & 2:
                                soff += 8   # pivot
                elif chunk_type == 0x2019:
                    palette_chunks += 1
                elif chunk_type == 0x2020:
                    userdata_chunks += 1
                coff += chunk_size
            off = frame_end
    except (ValueError, struct.error) as exc:
        return _identified(
            "aseprite", name, source_split, header,
            f"chunk walk failed ({exc}); header facts only",
            probe)
    facts = dict(header)
    facts.update({
        "frames_parsed": frames_declared,
        "layers": layers,
        "layer_count": len(layers),
        "cel_count": cels,
        "tags": tags,
        "tag_count": len(tags),
        "slices": slices,
        "slice_count": len(slices),
        "palette_chunk_count": palette_chunks,
        "userdata_chunk_count": userdata_chunks,
        "chunk_type_counts": chunk_types,
    })
    return _record("aseprite", name, source_split, "decoded",
                   facts)


# ------------------------------------------------------------------
# 5. Godot AnimationPlayer / AnimationTree (.tscn/.tres text)
# ------------------------------------------------------------------
_GD_SECTION_RE = re.compile(r"^\[(.+?)\]\s*$", re.M)
_GD_ATTR_RE = re.compile(r'(\w+)\s*=\s*("[^"]*"|[^\s\]]+)')
_GD_SUBRESOURCE_REF_RE = re.compile(
    r'"([^"]+)"\s*:\s*SubResource\(\s*"?([^"\s\)]+)"?\s*\)')


def _gd_sections(text):
    matches = list(_GD_SECTION_RE.finditer(text))
    sections = []
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) \
            else len(text)
        sections.append((m.group(1), text[m.end():end]))
    return sections


def _gd_attrs(raw):
    attrs = {}
    for key, val in _GD_ATTR_RE.findall(raw):
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        attrs[key] = val
    return attrs


def _gd_prop(body, key):
    m = re.search(r"^%s\s*=\s*(.+)$" % re.escape(key), body,
                  re.M)
    return m.group(1).strip() if m else None


def _gd_animation_from_body(body, anim_id, lib_names):
    resource_name = _gd_prop(body, "resource_name")
    if resource_name and resource_name.startswith('"'):
        resource_name = resource_name.strip('"')
    name = resource_name or lib_names.get(anim_id) or anim_id
    length_raw = _gd_prop(body, "length")
    try:
        length = float(length_raw) if length_raw else None
    except ValueError:
        length = None
    track_ids = set()
    track_paths = []
    for m in re.finditer(r"tracks/(\d+)/type\s*=", body):
        track_ids.add(int(m.group(1)))
    for m in re.finditer(
            r'tracks/(\d+)/path\s*=\s*NodePath\("([^"]*)"\)',
            body):
        if m.group(2) not in track_paths:
            track_paths.append(m.group(2))
    keys = 0
    for m in re.finditer(
            r'"times"\s*:\s*PackedFloat32Array\(([^)]*)\)',
            body):
        inner = m.group(1).strip()
        if inner:
            keys += len([p for p in inner.split(",")
                         if p.strip()])
    return {"name": name, "id": anim_id, "length": length,
            "tracks": len(track_ids),
            "track_paths_sample": track_paths[:8],
            "keys": keys,
            "keys_basis": "summed lengths of the tracks' "
                          "\"times\" PackedFloat32Array "
                          "entries (Godot 4 packed keys)"}


def parse_godot_text(text, name, source_split=None):
    if "Animation" not in text:
        return None
    # AnimationLibrary key -> animation sub-resource id map
    # (data = { "idle": SubResource("Animation_1"), ... }).
    lib_names = {}
    for m in _GD_SUBRESOURCE_REF_RE.finditer(text):
        lib_names[m.group(2)] = m.group(1)
    animations = []
    players = []
    trees = []
    state_machines = []
    for header, body in _gd_sections(text):
        attrs = _gd_attrs(header)
        if header.startswith("sub_resource") \
                or header.startswith("gd_resource"):
            rtype = attrs.get("type")
            rid = attrs.get("id")
            if rtype == "Animation":
                animations.append(_gd_animation_from_body(
                    body, rid, lib_names))
            elif rtype == "AnimationNodeStateMachine":
                states = []
                for m in re.finditer(
                        r"^states/([^/\s]+)/node\s*=", body,
                        re.M):
                    if m.group(1) not in states:
                        states.append(m.group(1))
                transitions = 0
                tm = re.search(r"^transitions\s*=\s*\[(.*?)\]",
                               body, re.M | re.S)
                if tm:
                    items = [p for p in tm.group(1).split(",")
                             if p.strip()]
                    transitions = len(items) // 3
                state_machines.append({
                    "id": rid, "states": states,
                    "transitions_count": transitions})
        elif header.startswith("node"):
            ntype = attrs.get("type")
            if ntype == "AnimationPlayer":
                autoplay = _gd_prop(body, "autoplay")
                lib_block = re.search(
                    r"^libraries\s*=\s*\{(.*?)\}", body,
                    re.M | re.S)
                libraries = re.findall(
                    r'SubResource\(\s*"?([^"\s\)]+)"?\s*\)',
                    lib_block.group(1) if lib_block else
                    (_gd_prop(body, "libraries") or ""))
                players.append({
                    "name": attrs.get("name"),
                    "libraries": libraries,
                    "autoplay": autoplay.strip('"')
                    if autoplay else None})
            elif ntype == "AnimationTree":
                root = re.search(
                    r'tree_root\s*=\s*SubResource\(\s*"?'
                    r'([^"\s\)]+)"?\s*\)', body)
                trees.append({
                    "name": attrs.get("name"),
                    "tree_root": root.group(1) if root
                    else None})
    if not animations and not players and not trees \
            and not state_machines:
        return None
    for tree in trees:
        tree["state_machines"] = state_machines
    facts = {"animations": animations,
             "animation_count": len(animations),
             "players": players,
             "player_count": len(players),
             "trees": trees,
             "tree_count": len(trees)}
    return _record("godot-animationplayer", name,
                   source_split, "decoded", facts)


# ------------------------------------------------------------------
# 6. Spriter (.scml XML)
# ------------------------------------------------------------------
def parse_spriter(data, name, source_split=None):
    probe = ("Fix the XML, or export the Spriter project "
             "again; only well-formed .scml decodes.")
    try:
        root = ET.fromstring(data.decode("utf-8", "replace"))
    except ET.ParseError as exc:
        return _identified("spriter", name, source_split, {},
                           f"XML parse failed ({exc})", probe)
    if root.tag.rsplit("}", 1)[-1] != "spriter_data" \
            and root.find(".//entity") is None:
        return None
    entities = []
    total_timelines = 0
    total_keys = 0
    for entity in root.iter("entity"):
        animations = []
        object_types = set()
        ent_timelines = 0
        ent_keys = 0
        for anim in entity.findall("animation"):
            timelines = anim.findall("timeline")
            keys = 0
            for timeline in timelines:
                keys += len(timeline.findall("key"))
                otype = timeline.get("object_type")
                if otype:
                    object_types.add(otype)
            try:
                length = int(anim.get("length"))
            except (TypeError, ValueError):
                length = None
            animations.append({
                "name": anim.get("name"), "length": length,
                "timelines": len(timelines),
                "keyframes": keys})
            ent_timelines += len(timelines)
            ent_keys += keys
        entities.append({
            "name": entity.get("name"),
            "animations": animations,
            "animation_count": len(animations),
            "timelines_count": ent_timelines,
            "keyframe_count": ent_keys,
            "object_types": sorted(object_types)})
        total_timelines += ent_timelines
        total_keys += ent_keys
    if not entities:
        return None
    facts = {"entities": entities,
             "entity_count": len(entities),
             "timelines_count": total_timelines,
             "keyframe_count": total_keys}
    return _record("spriter", name, source_split, "decoded",
                   facts)


# ------------------------------------------------------------------
# 7. Rive (.riv header only)
# ------------------------------------------------------------------
def parse_rive(data, name, source_split=None):
    if data[:4] != b"RIVE":
        return None
    probe = ("Add a Rive property-stream decoder (varint "
             "property keys and the core object table), or "
             "inspect the file in the Rive editor/runtime.")
    try:
        major, off = _read_varint(data, 4)
        minor, off = _read_varint(data, off)
        file_id, off = _read_varint(data, off)
    except ValueError as exc:
        return _identified(
            "rive", name, source_split, {},
            f"RIVE header varints do not parse ({exc})",
            probe)
    facts = {"major_version": major, "minor_version": minor,
             "file_id": file_id}
    return _identified(
        "rive", name, source_split, facts,
        "property-stream decode not implemented; only the "
        "RIVE header (magic, major/minor version, file id) "
        "is parsed", probe)


# ------------------------------------------------------------------
# 8. Unity Animator / AnimationClip (loose YAML text)
# ------------------------------------------------------------------
_UNITY_CURVE_KEYS = ("m_PositionCurves", "m_RotationCurves",
                     "m_EulerCurves", "m_ScaleCurves",
                     "m_FloatCurves")
_UNITY_CLASS_KINDS = {74: "AnimationClip",
                      91: "AnimatorController",
                      221: "AnimatorOverrideController",
                      1107: "AnimatorStateMachine",
                      1102: "AnimatorState",
                      1101: "AnimatorStateTransition"}


def _unity_list_count(body, key):
    """Count list entries under one ``key:`` block in Unity
    YAML (bounded textual count)."""
    lines = body.splitlines()
    count = 0
    in_block = False
    base_indent = None
    for line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if not in_block:
            if re.match(r"%s\s*:\s*$" % re.escape(key),
                        stripped):
                in_block = True
                base_indent = indent
            continue
        if not stripped:
            continue
        if indent <= base_indent and not stripped.startswith("-"):
            break
        if stripped.startswith("- "):
            count += 1
    return count


def parse_unity_yaml(text, name, source_split=None):
    if "!u!" not in text:
        return _identified(
            "unity-animator", name, source_split, {},
            "file carries a Unity animation extension but "
            "no Unity YAML document header (--- !u!<class>); "
            "identified by extension only",
            "Open the file as text: loose Unity animation "
            "assets are YAML; a binary serialized file "
            "needs the bundle rung (UnityPy).")
    docs = []
    chunks = re.split(r"^--- !u!(\d+) &(\d+).*$", text,
                      flags=re.M)
    # chunks: [prelude, class, anchor, body, class, anchor, ...]
    parsed = []
    for i in range(1, len(chunks) - 2, 3):
        parsed.append((int(chunks[i]), chunks[i + 1],
                       chunks[i + 2]))
    state_names = {}
    for class_id, anchor, body in parsed:
        if class_id == 1102:
            m = re.search(r"^  m_Name:\s*(.+)$", body, re.M)
            if m:
                state_names[anchor] = m.group(1).strip()
    for class_id, anchor, body in parsed:
        kind = _UNITY_CLASS_KINDS.get(
            class_id, f"class-{class_id}")
        m = re.search(r"^  m_Name:\s*(.+)$", body, re.M)
        doc = {"class_id": class_id, "kind": kind,
               "anchor": anchor,
               "name": m.group(1).strip() if m else None}
        if class_id == 74:  # AnimationClip
            legacy = re.search(r"^  m_Legacy:\s*(\d+)", body,
                               re.M)
            stop = re.search(r"m_StopTime:\s*([0-9.]+)", body)
            rate = re.search(r"m_SampleRate:\s*([0-9.]+)",
                             body)
            doc["legacy"] = int(legacy.group(1)) \
                if legacy else None
            doc["stop_time"] = float(stop.group(1)) \
                if stop else None
            doc["sample_rate"] = float(rate.group(1)) \
                if rate else None
            curves = {}
            current = None
            counts = {k: 0 for k in _UNITY_CURVE_KEYS}
            for line in body.splitlines():
                stripped = line.strip()
                header = re.match(
                    r"(m_\w+Curves)\s*:\s*$", stripped)
                if header and header.group(1) in counts:
                    current = header.group(1)
                elif re.match(r"m_\w+\s*:", stripped):
                    current = None
                if current and re.match(r"-\s+curve\s*:",
                                        stripped):
                    counts[current] += 1
            curves = {k: v for k, v in counts.items() if v}
            doc["curve_counts"] = curves
            doc["curve_count_basis"] = (
                "textual count of '- curve:' entries under "
                "each m_*Curves block")
            doc["curve_count_total"] = sum(curves.values())
        elif class_id == 91:  # AnimatorController
            params = []
            for pm in re.finditer(
                    r"-\s*m_Name:\s*(.+)\n\s*m_Type:\s*(\d+)",
                    body):
                params.append({"name": pm.group(1).strip(),
                               "type": int(pm.group(2))})
            doc["parameters"] = params
            doc["parameter_count"] = len(params)
            doc["state_machine_refs"] = len(re.findall(
                r"m_StateMachine\s*:", body))
        elif class_id == 1107:  # AnimatorStateMachine
            child_states = []
            for sm in re.finditer(
                    r"m_State:\s*\{fileID:\s*(\d+)\}", body):
                child_states.append(state_names.get(
                    sm.group(1), f"fileID {sm.group(1)}"))
            doc["child_states"] = child_states
            doc["child_state_count"] = len(child_states)
            doc["any_state_transitions_count"] = \
                _unity_list_count(body, "m_AnyStateTransitions")
        docs.append(doc)
    relevant = [d for d in docs
                if d["class_id"] in (74, 91, 221)]
    if not relevant:
        return None
    facts = {
        "documents": docs,
        "document_count": len(docs),
        "clip_count": sum(1 for d in docs
                          if d["class_id"] == 74),
        "controller_count": sum(1 for d in docs
                                if d["class_id"] in (91, 221)),
        "names": [d["name"] for d in relevant if d["name"]],
        "parameters": [p for d in docs
                       for p in d.get("parameters") or []],
        "state_machines": [
            {"name": d["name"],
             "child_states": d.get("child_states") or [],
             "any_state_transitions_count":
                 d.get("any_state_transitions_count", 0)}
            for d in docs if d["class_id"] == 1107],
    }
    return _record("unity-animator", name, source_split,
                   "decoded", facts)


def _is_unity_data_member(low):
    """True for members that can carry Unity serialized
    data: bundle/.assets files anywhere, split parts of an
    .assets file, and the classic serialized-data tree
    under a bin/Data directory (extensionless hash-named
    files, level files, shared-assets files and their split
    parts). Raw .resource payloads (media bytes referenced
    by serialized files, not serialized data themselves)
    and the IL2CPP metadata subtree (engine type tables,
    present whether or not the game ships animation) are
    excluded."""
    base = low.rsplit("/", 1)[-1]
    if "/managed/" in low or base == "global-metadata.dat":
        return False
    if low.endswith((".bundle", ".unity3d", ".assets")):
        return True
    if re.search(r"\.assets\.split\d+$", low):
        return True
    if "/bin/data/" in low \
            and not low.endswith(".resource"):
        return True
    return False


def parse_unity_bundle_member(data, name, source_split=None):
    """Identification only for clips/controllers embedded
    in a Unity bundle/.assets member: bounded content scan
    for the serialized type names."""
    found = []
    if b"AnimationClip" in data:
        found.append("AnimationClip")
    if b"AnimatorController" in data:
        found.append("AnimatorController")
    if not found:
        return None
    return _identified(
        "unity-animator", name, source_split,
        {"embedded_types": found},
        "AnimationClip/AnimatorController content is "
        "embedded in a Unity bundle/.assets member; loose-"
        "file YAML decode does not apply inside bundles",
        "Add a UnityPy rung to enumerate serialized objects "
        "inside UnityFS bundles and .assets files.")


# ------------------------------------------------------------------
# 9. Cocos (.ccb plist / .csb binary)
# ------------------------------------------------------------------
def _ccb_node_count(node, budget):
    count = 0
    if budget[0] <= 0:
        return count
    if isinstance(node, dict):
        budget[0] -= 1
        count += 1
        children = node.get("children")
        if isinstance(children, list):
            for child in children:
                count += _ccb_node_count(child, budget)
    return count


def parse_ccb(data, name, source_split=None):
    probe = ("Convert the .ccb to its XML plist form, or "
             "add a CocosBuilder binary reader for the "
             "non-plist variant.")
    try:
        root = plistlib.loads(data)
    except Exception as exc:  # plistlib raises several types
        return _identified(
            "cocos-ccb", name, source_split, {},
            f"plistlib could not parse the .ccb ({exc}); "
            f"identified by extension only", probe)
    if not isinstance(root, dict) or not (
            {"nodeGraph", "sequences", "resolutions"}
            & set(root)):
        return _identified(
            "cocos-ccb", name, source_split, {},
            "plist parsed but carries none of the Cocos "
            "Builder root keys (nodeGraph/sequences/"
            "resolutions)", probe)
    budget = [10000]
    node_count = _ccb_node_count(root.get("nodeGraph"),
                                 budget)
    sequences = []
    for seq in root.get("sequences") or []:
        if isinstance(seq, dict):
            sequences.append({"name": seq.get("name"),
                              "length": seq.get("length")})
    facts = {"node_count": node_count,
             "node_count_capped": budget[0] <= 0,
             "sequences": sequences,
             "sequence_count": len(sequences),
             "resolutions_count": len(
                 root.get("resolutions") or [])}
    return _record("cocos-ccb", name, source_split,
                   "decoded", facts)


def parse_csb(data, name, source_split=None):
    return _identified(
        "cocos-ccb", name, source_split,
        {"size_bytes": len(data),
         "first_bytes_hex": data[:16].hex()},
        "CSB is a custom FlatBuffers-based binary (Cocos "
        "Studio); node-graph decode is not implemented, "
        "identification and first-bytes facts only",
        "Add a CSB FlatBuffers reader (timeline/node "
        "tables) with a labeled fixture.")


# ------------------------------------------------------------------
# 10. GIF (.gif image sequence)
# ------------------------------------------------------------------
_GIF_MAGICS = (b"GIF87a", b"GIF89a")


def _gif_skip_sub_blocks(data, pos):
    """Offset just past a GIF data sub-block series (a run
    of length-prefixed blocks ended by a zero length), or
    None when the series runs past the end of the data."""
    while True:
        if pos >= len(data):
            return None
        size = data[pos]
        pos += 1
        if size == 0:
            return pos
        pos += size
        if pos > len(data):
            return None


def parse_gif(data, name, source_split=None):
    """GIF structural parse: the 6-byte version magic, the
    logical-screen width/height, then a block walk counting
    image descriptors (frames) and graphic-control
    extensions (with their delay values), plus the
    NETSCAPE2.0 looping extension when present. A member
    whose walk does not reach the trailer byte degrades to
    identified_only with the header facts only — a frame
    count is never claimed from a partial walk."""
    probe = ("Repair or re-export the GIF; only a block "
             "walk that reaches the trailer byte supports "
             "a frame count.")
    if len(data) < 13 or data[:6] not in _GIF_MAGICS:
        return _identified(
            "gif", name, source_split, {},
            "member carries a .gif name but no GIF87a/"
            "GIF89a magic at its start; identified by "
            "extension only", probe)
    version = data[:6].decode("ascii")
    width, height = struct.unpack_from("<HH", data, 6)
    header = {"version": version, "width": width,
              "height": height}
    pos = 13
    packed = data[10]
    if packed & 0x80:
        pos += 3 * (2 ** ((packed & 0x07) + 1))
    frames = 0
    delays = []
    loop_count = None
    problem = None
    while problem is None:
        if pos >= len(data):
            problem = "data ends before the trailer byte"
            break
        marker = data[pos]
        if marker == 0x3B:  # trailer
            break
        if marker == 0x21:  # extension block
            if pos + 2 > len(data):
                problem = "truncated extension header"
                break
            label = data[pos + 1]
            end = _gif_skip_sub_blocks(data, pos + 2)
            if end is None:
                problem = "extension sub-blocks run past " \
                          "the end of the data"
                break
            if label == 0xF9:  # graphic control extension
                # One sub-block: packed, delay u16 (in
                # centiseconds), transparent-colour index.
                if pos + 5 <= len(data) \
                        and data[pos + 2] == 4:
                    delay, = struct.unpack_from(
                        "<H", data, pos + 4)
                    delays.append(delay)
            elif label == 0xFF:  # application extension
                # First sub-block is the 11-byte application
                # identifier; NETSCAPE2.0 carries the loop
                # count in a following 3-byte sub-block
                # (sub-block id 1, then a u16 count).
                if data[pos + 3:pos + 14] == b"NETSCAPE2.0" \
                        and pos + 18 <= len(data) \
                        and data[pos + 14] == 3 \
                        and data[pos + 15] == 1:
                    loop_count, = struct.unpack_from(
                        "<H", data, pos + 16)
            pos = end
            continue
        if marker == 0x2C:  # image descriptor
            if pos + 10 > len(data):
                problem = "truncated image descriptor"
                break
            ipacked = data[pos + 9]
            pos += 10
            if ipacked & 0x80:  # local colour table
                pos += 3 * (2 ** ((ipacked & 0x07) + 1))
            if pos >= len(data):
                problem = "image data runs past the end " \
                          "of the data"
                break
            pos += 1  # LZW minimum code size byte
            end = _gif_skip_sub_blocks(data, pos)
            if end is None:
                problem = "image sub-blocks run past " \
                          "the end of the data"
                break
            frames += 1
            pos = end
            continue
        problem = f"unknown block byte {marker:#04x} at " \
                  f"offset {pos}"
    if problem is not None:
        return _identified(
            "gif", name, source_split, header,
            f"GIF block walk failed ({problem}); header "
            f"facts only, no frame count claimed", probe)
    facts = dict(header)
    facts.update({
        "frame_count": frames,
        "animated": frames > 1,
        "frame_delays_cs": delays[:16],
        "frame_delays_truncated": len(delays) > 16,
        "loop_count": loop_count,
    })
    return _record("gif", name, source_split, "decoded",
                   facts)


# ------------------------------------------------------------------
# 11. PAG (.pag binary)
# ------------------------------------------------------------------
def parse_pag(data, name, source_split=None):
    """Identification only for PAG animation files: the
    format is a proprietary binary container and this rung
    does not decode its tag stream, so the record carries
    size and first-bytes facts only. Identification rests
    on the .pag extension itself — a library or version
    file whose name merely contains the substring is not
    a PAG animation file and never reaches this parser."""
    return _identified(
        "pag", name, source_split,
        {"size_bytes": len(data),
         "first_bytes_hex": data[:16].hex()},
        "PAG is a proprietary binary animation format; "
        "container decode is not implemented, identification "
        "and first-bytes facts only",
        "Add a PAG container reader (tag-stream walk) "
        "with a labeled fixture.")


# ------------------------------------------------------------------
# 12. Android view animation (res/anim, res/animator XML)
# ------------------------------------------------------------------
_ANIM_ROOTS = frozenset((
    "set", "alpha", "scale", "translate", "rotate", "clip",
    "objectAnimator", "animator", "layoutAnimation",
    "gridLayoutAnimation"))
_INTERPOLATOR_ROOTS = frozenset((
    "accelerateDecelerateInterpolator",
    "accelerateInterpolator", "anticipateInterpolator",
    "anticipateOvershootInterpolator", "bounceInterpolator",
    "cycleInterpolator", "decelerateInterpolator",
    "linearInterpolator", "overshootInterpolator",
    "pathInterpolator"))
_ANIM_DIR_RE = re.compile(
    r"(?:^|/)res/(anim|animator)(?:-[^/]*)?/")

_ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _anim_resource_kind(name):
    """'anim' / 'animator' when the member sits in a view-
    animation resource directory (res/anim, res/animator,
    with any qualifier suffix), else None."""
    m = _ANIM_DIR_RE.search(name.lower())
    return m.group(1) if m else None


def _axml_read_len8(data, pos):
    b0 = data[pos]
    if b0 & 0x80:
        return ((b0 & 0x7F) << 8) | data[pos + 1], pos + 2
    return b0, pos + 1


def _axml_read_len16(data, pos):
    v = struct.unpack_from("<H", data, pos)[0]
    if v & 0x8000:
        v2 = struct.unpack_from("<H", data, pos + 2)[0]
        return ((v & 0x7FFF) << 16) | v2, pos + 4
    return v, pos + 2


def _axml_string_pool(data, chunk_off):
    """String list of one AXML string-pool chunk (the same
    layout nar-perms' manifest reader walks)."""
    header_size = struct.unpack_from(
        "<H", data, chunk_off + 2)[0]
    string_count, _styles, flags, strings_start, _ss = \
        struct.unpack_from("<IIIII", data, chunk_off + 8)
    utf8 = bool(flags & 0x100)
    offsets_base = chunk_off + header_size
    strings_base = chunk_off + strings_start
    strings = []
    for i in range(string_count):
        off = struct.unpack_from(
            "<I", data, offsets_base + i * 4)[0]
        pos = strings_base + off
        if utf8:
            _chars, pos = _axml_read_len8(data, pos)
            byte_len, pos = _axml_read_len8(data, pos)
            strings.append(data[pos:pos + byte_len].decode(
                "utf-8", "replace"))
        else:
            char_len, pos = _axml_read_len16(data, pos)
            strings.append(
                data[pos:pos + char_len * 2].decode(
                    "utf-16-le", "replace"))
    return strings


def _axml_attr_value(strings, raw_value, data_type, data):
    if raw_value != 0xFFFFFFFF:
        return strings[raw_value] \
            if raw_value < len(strings) else None
    if data_type == 0x03:  # TYPE_STRING
        return strings[data] if data < len(strings) else None
    if data_type == 0x12:  # TYPE_INT_BOOLEAN
        return bool(data)
    if data_type == 0x10:  # TYPE_INT_DEC
        return data if data < 0x80000000 \
            else data - 0x100000000
    if data_type == 0x01:  # TYPE_REFERENCE
        return f"@0x{data:08x}"
    if data_type == 0x02:  # TYPE_ATTRIBUTE
        return f"?0x{data:08x}"
    return f"0x{data:08x}"


def _parse_axml_tree(data):
    """Binary-XML (AXML) bytes -> a node tree of
    {tag, attrs, children} dicts, or None when the bytes
    are not a well-formed AXML document. The walk mirrors
    nar-perms' manifest reader (string pool plus
    start/end-element chunks); only element structure and
    attributes are kept."""
    if len(data) < 8 or struct.unpack_from(
            "<I", data, 0)[0] != 0x00080003:
        return None
    strings = []
    root = None
    stack = []
    off = 8
    try:
        while off + 8 <= len(data):
            chunk_type, _hs, chunk_size = struct.unpack_from(
                "<HHI", data, off)
            if chunk_size < 8 or off + chunk_size > len(data):
                return None
            if chunk_type == 0x0001:  # string pool
                strings = _axml_string_pool(data, off)
            elif chunk_type == 0x0102:  # start element
                _ns, name_idx = struct.unpack_from(
                    "<II", data, off + 16)
                attr_start, attr_size, attr_count = \
                    struct.unpack_from("<HHH", data, off + 24)
                tag = strings[name_idx] \
                    if name_idx < len(strings) else ""
                node = {"tag": tag, "attrs": {},
                        "children": []}
                for i in range(attr_count):
                    a_off = off + 16 + attr_start \
                        + i * attr_size
                    a_ns, a_name, a_raw, _sz, _z, a_type, \
                        a_data = struct.unpack_from(
                            "<IIIHBBI", data, a_off)
                    key = strings[a_name] \
                        if a_name < len(strings) else ""
                    if a_ns != 0xFFFFFFFF \
                            and a_ns < len(strings) \
                            and strings[a_ns] == _ANDROID_NS:
                        key = "android:" + key
                    node["attrs"][key] = _axml_attr_value(
                        strings, a_raw, a_type, a_data)
                if stack:
                    stack[-1]["children"].append(node)
                elif root is None:
                    root = node
                stack.append(node)
            elif chunk_type == 0x0103:  # end element
                if stack:
                    stack.pop()
            off += chunk_size
    except (struct.error, IndexError):
        return None
    return root


def _et_node(elem):
    tag = elem.tag.rsplit("}", 1)[-1] \
        if isinstance(elem.tag, str) else ""
    attrs = {}
    for key, val in elem.attrib.items():
        attrs[key.rsplit("}", 1)[-1]] = val
        attrs[key] = val
    return {"tag": tag, "attrs": attrs,
            "children": [_et_node(c) for c in elem]}


def _parse_text_xml_tree(data):
    try:
        root = ET.fromstring(data.decode("utf-8", "replace"))
    except ET.ParseError:
        return None
    return _et_node(root)


def _android_view_facts(root, kind):
    kinds = {}
    durations = set()
    interpolators = set()
    properties = set()
    count = 0
    stack = [root]
    while stack:
        node = stack.pop()
        count += 1
        kinds[node["tag"]] = kinds.get(node["tag"], 0) + 1
        attrs = node["attrs"]
        for key in ("android:duration", "duration"):
            val = attrs.get(key)
            if isinstance(val, bool):
                continue
            if isinstance(val, int):
                durations.add(val)
            elif isinstance(val, str) and val.isdigit():
                durations.add(int(val))
        for key in ("android:interpolator", "interpolator"):
            val = attrs.get(key)
            if isinstance(val, str) and val:
                interpolators.add(val)
        for key in ("android:propertyName", "propertyName"):
            val = attrs.get(key)
            if isinstance(val, str) and val:
                properties.add(val)
        stack.extend(node["children"])
    return {
        "root": root["tag"],
        "resource_kind": kind,
        "element_count": count,
        "element_kinds": {k: kinds[k] for k in sorted(kinds)},
        "durations_ms": sorted(durations)[:16],
        "interpolators": sorted(interpolators)[:8],
        "property_names": sorted(properties)[:8],
    }


def parse_android_view(data, name, source_split=None):
    """Android view/property animation resource decode.

    The member must sit in a res/anim or res/animator
    directory (any qualifier variant) — or be a loose file,
    where content alone decides — and its XML root must be
    an animation element (set / alpha / scale / translate /
    rotate / clip / objectAnimator / animator /
    layoutAnimation, an interpolator element, or a selector
    holding animator children). Binary AXML is walked with
    the built-in reader; plain-text XML is parsed as XML.
    A directory-matched member whose bytes parse as
    neither degrades to identified_only; anything else is
    not a view-animation record at all."""
    kind = _anim_resource_kind(name) or "loose"
    root = None
    if data[:4] == b"\x03\x00\x08\x00":
        root = _parse_axml_tree(data)
    elif data.lstrip()[:1] == b"<":
        root = _parse_text_xml_tree(data)
    if root is None:
        if kind != "loose":
            return _identified(
                "android-view", name, source_split, {},
                "member sits in a view-animation resource "
                "directory but its XML does not parse as "
                "binary or text XML; identified by "
                "directory only",
                "Dump the resource with aapt2 to inspect "
                "the compiled XML.")
        return None
    tag = root["tag"]
    is_animation = tag in _ANIM_ROOTS \
        or tag in _INTERPOLATOR_ROOTS
    if not is_animation and tag == "selector":
        stack = list(root["children"])
        while stack and not is_animation:
            node = stack.pop()
            if node["tag"] in ("objectAnimator", "animator"):
                is_animation = True
            stack.extend(node["children"])
    if not is_animation:
        return None
    facts = _android_view_facts(root, kind)
    return _record("android-view", name, source_split,
                   "decoded", facts)


# ------------------------------------------------------------------
# Dispatch: one member -> one record (or None)
# ------------------------------------------------------------------
_EXT_SYSTEM_GUESS = {
    ".skel": "spine", ".riv": "rive", ".ase": "aseprite",
    ".aseprite": "aseprite", ".tscn": "godot-animationplayer",
    ".tres": "godot-animationplayer", ".scml": "spriter",
    ".anim": "unity-animator",
    ".controller": "unity-animator",
    ".overridecontroller": "unity-animator",
    ".ccb": "cocos-ccb", ".csb": "cocos-ccb",
    ".gif": "gif", ".pag": "pag",
}


def _parse_json_member(data, name, source_split):
    low = name.lower()
    try:
        obj = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        if low.endswith("_ske.json"):
            return _identified(
                "dragonbones", name, source_split, {},
                f"DragonBones skeleton JSON does not parse "
                f"({exc})",
                "Repair the JSON export; the *_ske.json "
                "structure is required for decode.")
        if low.endswith("_tex.json"):
            return _identified(
                "dragonbones", name, source_split, {},
                f"DragonBones texture JSON does not parse "
                f"({exc})",
                "Repair the JSON export; the *_tex.json "
                "structure is required for decode.")
        return None
    if _is_dragonbones_ske(obj) or low.endswith("_ske.json"):
        if _is_dragonbones_ske(obj):
            return parse_dragonbones_ske(obj, name,
                                         source_split)
        return _identified(
            "dragonbones", name, source_split, {},
            "*_ske.json name but no armature list with bone "
            "arrays in the document",
            "Export the skeleton from DragonBones as "
            "*_ske.json with armature/bone structure.")
    if _is_dragonbones_tex(obj) or low.endswith("_tex.json"):
        if _is_dragonbones_tex(obj):
            return parse_dragonbones_tex(obj, name,
                                         source_split)
        return _identified(
            "dragonbones", name, source_split, {},
            "*_tex.json name but no SubTexture list / "
            "imagePath in the document",
            "Export the texture atlas from DragonBones as "
            "*_tex.json.")
    if is_spine_json(obj):
        return parse_spine_json(obj, name, source_split)
    if is_lottie(obj):
        return parse_lottie(obj, name, source_split)
    if is_creature(obj):
        return parse_creature(obj, name, source_split)
    return None


def classify_and_parse(name, data, source_split=None):
    """One archive member -> one animation record or None.

    Detection is structural; extension-only candidates that
    fail their structure guards degrade to identified_only
    records (never garbage counts)."""
    low = name.lower()
    try:
        if low.endswith(".json"):
            return _parse_json_member(data, name, source_split)
        if low.endswith(".skel"):
            return parse_spine_skel(data, name, source_split)
        if low.endswith(".riv"):
            return parse_rive(data, name, source_split)
        if low.endswith((".ase", ".aseprite")):
            return parse_aseprite(data, name, source_split)
        if low.endswith((".tscn", ".tres")):
            return parse_godot_text(
                data.decode("utf-8", "replace"), name,
                source_split)
        if low.endswith(".scml"):
            return parse_spriter(data, name, source_split)
        if low.endswith((".anim", ".controller",
                         ".overridecontroller")):
            return parse_unity_yaml(
                data.decode("utf-8", "replace"), name,
                source_split)
        if low.endswith(".ccb"):
            return parse_ccb(data, name, source_split)
        if low.endswith(".csb"):
            return parse_csb(data, name, source_split)
        if low.endswith(".gif"):
            return parse_gif(data, name, source_split)
        if low.endswith(".pag"):
            return parse_pag(data, name, source_split)
        if low.endswith(".xml"):
            return parse_android_view(data, name,
                                      source_split)
        if _is_unity_data_member(low):
            return parse_unity_bundle_member(data, name,
                                             source_split)
    except Exception as exc:  # per-file degradation, by design
        system = _EXT_SYSTEM_GUESS.get(
            os.path.splitext(low)[1], "unknown")
        if system == "unknown" and low.endswith(
                (".json", ".xml")):
            return None
        return _identified(
            system, name, source_split, {},
            f"parser failed on this member ({exc}); "
            f"identified by extension only",
            "Inspect the member manually; if it is a valid "
            "file of its format, the parser needs a fixture "
            "for this variant.")
    return None


def is_candidate(name):
    low = name.lower()
    if low.endswith(".xml"):
        # XML members are read only when they can be view-
        # animation resources: inside a res/anim or
        # res/animator directory, or a loose file whose
        # content decides.
        return _anim_resource_kind(name) is not None \
            or "/" not in name
    if _is_unity_data_member(low):
        return True
    return low.endswith((
        ".json", ".skel", ".riv", ".ase", ".aseprite",
        ".tscn", ".tres", ".scml", ".anim", ".controller",
        ".overridecontroller", ".ccb", ".csb",
        ".gif", ".pag"))


# ------------------------------------------------------------------
# 11. Physics-rig detection (symbol clusters + part naming)
# ------------------------------------------------------------------
_BOX2D_TOKENS = ("b2World", "b2Body", "b2Joint", "b2Fixture",
                 "b2Shape", "b2Contact", "b2RevoluteJoint",
                 "b2PrismaticJoint", "b2DistanceJoint",
                 "b2WeldJoint", "b2PolygonShape",
                 "b2CircleShape")
_CHIPMUNK_TOKENS = ("cpSpace", "cpBody", "cpConstraint",
                    "cpShape", "cpJoint", "cpArbiter",
                    "cpSegmentShape", "cpCircleShape",
                    "cpPolyShape")
_PHYSICS_FAMILIES = (
    ("box2d", "Box2D", _BOX2D_TOKENS),
    ("chipmunk", "Chipmunk", _CHIPMUNK_TOKENS),
)

PART_TOKENS = frozenset((
    "wheel", "wheels", "chassis", "spring", "springs", "arm",
    "arms", "leg", "legs", "door", "hood", "axle", "tire",
    "tyre", "rim", "shock", "strut", "suspension", "bumper",
    "seat", "fork", "frame", "torso", "head", "foot",
    "feet", "hand", "hands", "tail", "wing", "wings",
    "pedal", "handle", "body"))


def elf_defined_exports(data, name="lib.so"):
    """Defined dynsym exports of one ELF blob ([] on any
    parse failure — a corrupt .so is no evidence)."""
    try:
        elf = Elf(data, name)
        return sorted({s["name"] for s in
                       elf.symbols(SHT_DYNSYM)
                       if s.get("defined") and s.get("name")})
    except (ElfError, Exception):
        return []


def detect_part_groups(member_names):
    """Sprite part-naming evidence: member basenames that
    share a prefix and carry a part token (wheel / chassis
    / spring / arm / leg / ...), grouped with >= 3 parts."""
    groups = {}
    for member in member_names:
        base = member.rsplit("/", 1)[-1]
        stem = os.path.splitext(base)[0]
        tokens = [t for t in re.split(r"[^A-Za-z0-9]+", stem)
                  if t]
        for idx, token in enumerate(tokens):
            if token.lower() not in PART_TOKENS:
                continue
            if idx == 0:
                continue
            prefix = stem[:stem.lower().find(token.lower())]
            prefix = prefix.rstrip("_-. ")
            if not prefix:
                continue
            directory = member.rsplit("/", 1)[0] \
                if "/" in member else ""
            key = (directory, prefix.lower())
            slot = groups.setdefault(key, {
                "prefix": prefix, "directory": directory,
                "files": [], "part_tokens": []})
            if member not in slot["files"]:
                slot["files"].append(member)
            if token.lower() not in slot["part_tokens"]:
                slot["part_tokens"].append(token.lower())
            break
    out = []
    for slot in groups.values():
        if len(slot["files"]) >= 3:
            slot = dict(slot)
            slot["files"] = sorted(slot["files"])
            slot["naming_pattern"] = (
                f"{slot['prefix']}_<part> "
                f"({', '.join(sorted(slot['part_tokens']))})")
            out.append(slot)
    out.sort(key=lambda g: (g["directory"], g["prefix"]))
    return out


def detect_physics(so_members, member_names):
    """Physics evidence over ``lib/**/*.so`` members.

    ``so_members`` is a list of (member name, bytes). A
    family cluster needs >= 3 distinct physics symbols of
    that family. Returns (rigs, part_groups): each rig is
    {engine_guess, family, symbol_count, sample,
    confidence, libraries, driver_candidate, driver_label,
    naming_evidence_present, note}."""
    per_family = {}
    libraries = set()
    for member, data in so_members:
        exports = elf_defined_exports(data, member)
        if not exports:
            continue
        for family, guess, tokens in _PHYSICS_FAMILIES:
            hits = {s for s in exports
                    if any(t in s for t in tokens)}
            if hits:
                slot = per_family.setdefault(
                    family, {"engine_guess": guess,
                             "symbols": set(),
                             "libraries": set()})
                slot["symbols"] |= hits
                slot["libraries"].add(member)
                libraries.add(member)
        generic = {s for s in exports
                   if not s.startswith("Java_")
                   and ("Joint" in s or "Spring" in s)}
        if generic:
            slot = per_family.setdefault(
                "generic-joint-spring",
                {"engine_guess": "generic physics "
                                 "(Joint/Spring exports)",
                 "symbols": set(), "libraries": set()})
            slot["symbols"] |= generic
            slot["libraries"].add(member)
    groups = detect_part_groups(member_names)
    rigs = []
    for family, slot in sorted(per_family.items()):
        symbols = sorted(slot["symbols"])
        if len(symbols) < 3:
            continue
        rigs.append({
            "engine_guess": slot["engine_guess"],
            "family": family,
            "symbol_count": len(symbols),
            "sample": symbols[:8],
            "confidence": "inferred",
            "libraries": sorted(slot["libraries"]),
            "driver_candidate": "physics",
            "driver_label": "inferred",
            "naming_evidence_present": bool(groups),
            "note": ("sprite part-naming evidence is "
                     "present, so a physics-driven "
                     "composition is emitted"
                     if groups else
                     "no sprite part-naming evidence "
                     "found; the physics driver remains a "
                     "candidate only (a symbol cluster "
                     "alone does not establish the driver)"),
        })
    return rigs, groups


# ------------------------------------------------------------------
# Composition records
# ------------------------------------------------------------------
def _stem_object(file_name, drop_suffixes=()):
    base = file_name.rsplit("/", 1)[-1]
    stem = os.path.splitext(base)[0]
    if stem.lower().endswith(".json"):
        stem = stem[:-5]
    for suffix in drop_suffixes:
        if stem.lower().endswith(suffix):
            stem = stem[:-len(suffix)]
    return stem or base


def build_compositions(systems, rigs, part_groups):
    """Composition records in the coordinator's shape:
    {object, classification, parts, naming_pattern,
    attachment_points, driver, driver_label, evidence,
    confidence}."""
    compositions = []
    for rec in systems:
        if rec.get("status") != "decoded":
            continue
        facts = rec.get("facts") or {}
        if rec["system"] == "spine":
            slots = facts.get("slots_detail") or []
            if not slots:
                continue
            compositions.append({
                "object": _stem_object(rec["file"]),
                "classification": None,
                "parts": [{"name": s["name"],
                           "role": "attachment",
                           "bone": s.get("bone")}
                          for s in slots],
                "naming_pattern": None,
                "attachment_points": [
                    {"slot": s["name"], "bone": s.get("bone")}
                    for s in slots],
                "driver": "skeletal",
                "driver_label": "observed",
                "evidence": [
                    f"{rec['file']}: {facts.get('bones_count')}"
                    f" bones, {facts.get('slots_count')} "
                    f"slots, {facts.get('animation_count')} "
                    f"animations (Spine slot->bone attachment "
                    f"data decoded)"],
                "confidence": "strongly-indicated"})
        elif rec["system"] == "dragonbones":
            for arm in facts.get("armatures") or []:
                slots = arm.get("slots_detail") or []
                if not slots:
                    continue
                compositions.append({
                    "object": arm.get("name")
                    or _stem_object(rec["file"], ("_ske",)),
                    "classification": None,
                    "parts": [{"name": s["name"],
                               "role": "attachment",
                               "bone": s.get("parent")}
                              for s in slots],
                    "naming_pattern": None,
                    "attachment_points": [
                        {"slot": s["name"],
                         "bone": s.get("parent")}
                        for s in slots],
                    "driver": "skeletal",
                    "driver_label": "observed",
                    "evidence": [
                        f"{rec['file']}: armature "
                        f"{arm.get('name')}: "
                        f"{arm.get('bones_count')} bones, "
                        f"{arm.get('slots_count')} slots, "
                        f"{arm.get('animation_count')} "
                        f"animations (DragonBones slot "
                        f"parent data decoded)"],
                    "confidence": "strongly-indicated"})
    if rigs and part_groups:
        rig = rigs[0]
        for group in part_groups:
            compositions.append({
                "object": group["prefix"],
                "classification": None,
                "parts": [{"name": f.rsplit("/", 1)[-1],
                           "role": "sprite-part",
                           "bone": None}
                          for f in group["files"]],
                "naming_pattern": group["naming_pattern"],
                "attachment_points": [],
                "driver": "physics",
                "driver_label": "inferred",
                "evidence": [
                    f"{', '.join(rig['libraries'])}: "
                    f"{rig['symbol_count']} {rig['engine_guess']}"
                    f" physics symbols (sample: "
                    f"{', '.join(rig['sample'][:3])})",
                    f"part naming: {group['naming_pattern']} "
                    f"over {len(group['files'])} files"],
                "confidence": "inferred"})
    return compositions


# ------------------------------------------------------------------
# Whole-target scan (nar-anim)
# ------------------------------------------------------------------
def scan_target(target):
    """The nar-anim report for one target path."""
    resolved = _container.resolve_target(target)
    try:
        container_block = resolved.container_block()
        roots = list(resolved.assets_roots)
        systems = []
        limitations = []
        so_members = []
        member_names = []
        loose = []
        if not roots:
            if zipfile.is_zipfile(target):
                roots = [os.path.abspath(target)]
            elif os.path.isfile(target):
                loose.append(os.path.abspath(target))
        for loose_path in loose:
            name = os.path.basename(loose_path)
            member_names.append(name)
            with open(loose_path, "rb") as fh:
                data = fh.read(MAX_MEMBER_BYTES + 1)
            if len(data) > MAX_MEMBER_BYTES:
                limitations.append(
                    f"{name}: file exceeds the "
                    f"{MAX_MEMBER_BYTES}-byte read cap; "
                    f"not decoded")
                continue
            if name.lower().endswith(".so"):
                so_members.append((name, data))
            rec = classify_and_parse(name, data, None)
            if rec:
                systems.append(rec)
        for root in roots:
            source_split = os.path.basename(root)
            try:
                zf = zipfile.ZipFile(root)
            except (zipfile.BadZipFile, OSError) as exc:
                limitations.append(
                    f"{source_split}: archive cannot be "
                    f"opened ({exc})")
                continue
            with zf:
                for info in zf.infolist():
                    name = info.filename
                    if name.endswith("/"):
                        continue
                    member_names.append(name)
                    low = name.lower()
                    is_so = low.startswith("lib/") \
                        and low.endswith(".so")
                    if not is_so and not is_candidate(name):
                        continue
                    if info.file_size > MAX_MEMBER_BYTES:
                        system = _EXT_SYSTEM_GUESS.get(
                            os.path.splitext(low)[1])
                        if system:
                            systems.append(_identified(
                                system, name, source_split,
                                {},
                                f"member declares "
                                f"{info.file_size} bytes, "
                                f"over the "
                                f"{MAX_MEMBER_BYTES}-byte "
                                f"read cap; not decoded",
                                "Extract the member and "
                                "decode it standalone, or "
                                "raise the cap for a "
                                "bounded local run."))
                        else:
                            limitations.append(
                                f"{name}: member exceeds "
                                f"the {MAX_MEMBER_BYTES}"
                                f"-byte read cap; skipped")
                        continue
                    try:
                        with zf.open(name) as fh:
                            data = fh.read(
                                MAX_MEMBER_BYTES + 1)
                    except (KeyError, OSError, RuntimeError,
                            zipfile.BadZipFile) as exc:
                        limitations.append(
                            f"{name}: member cannot be "
                            f"read ({exc})")
                        continue
                    if is_so:
                        so_members.append((name, data))
                        continue
                    rec = classify_and_parse(
                        name, data, source_split)
                    if rec:
                        systems.append(rec)
        rigs, part_groups = detect_physics(so_members,
                                           member_names)
        compositions = build_compositions(systems, rigs,
                                          part_groups)
        for rec in systems:
            if rec["status"] == "identified_only" \
                    and rec.get("reason"):
                limitations.append(
                    f"{rec['system']} in {rec['file']}: "
                    f"{rec['reason']}")
        if part_groups and not rigs:
            limitations.append(
                "sprite part-naming groups were found but "
                "no physics symbol cluster, so no physics "
                "driver is claimed")
        return {"version": VERSION,
                "target": os.path.abspath(target),
                "container": container_block,
                "systems": systems,
                "compositions": compositions,
                "physics_rigs": rigs,
                "limitations": limitations}
    finally:
        resolved.cleanup()
