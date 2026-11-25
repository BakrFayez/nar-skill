"""Texture-atlas parsers (Part 4 section 4.1).

One uniform record for every supported atlas format:

    {format, texture, page_width, page_height,
     frames: [{name, x, y, w, h, rotated,
               source_w, source_h, offset_x, offset_y}],
     frame_count, packed_area, page_area, rotated_count,
     error}

Fields a format does not carry are null, never guessed:
page dimensions are null when the atlas file does not state
them (Godot .tres, Unity .spriteatlas), and the texture name
is null when no page image is named. Where a format carries
no trim information the sprite is untrimmed by definition,
so source_w/source_h default to the frame size and the
offsets default to 0.

Parsers implemented (standard library only):

- Cocos2d plist atlases (XML or binary, via plistlib),
  format 1/2/3 frame styles, plus Cocos particle plists,
  which return a particle record instead of an atlas record.
- TexturePacker JSON (hash and array variants) and the
  Phaser 3 multi-texture variant (one record per page).
- Starling XML and TexturePacker XML atlases.
- libGDX .atlas / .pack text atlases (one record per page,
  both the xy/size and the bounds/offsets region styles).
- Godot .tres AtlasTexture resources (standalone .tres
  files only; AtlasTexture sub-resources embedded in .tscn
  scene text are out of scope for this parser).
- Unity .spriteatlas text YAML: the packed sprites are
  referenced by GUID only, so frame names and rects are NOT
  recoverable from the file alone. The record carries the
  atlas name, the packed-sprite count and
  names_recoverable=False instead of invented frames.

Every parser degrades to a record with ``error`` set rather
than raising: a malformed member must never crash a run.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import plistlib
import re
import xml.etree.ElementTree as ET

# ----------------------------------------------------------------
# Small coercion helpers
# ----------------------------------------------------------------

_NUM_RE = re.compile(r"-?\d+(?:\.\d+)?")


def _num(value):
    """Coerce a plist/JSON/text scalar to int (when integral)
    or float; None when the value carries no number."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value) if float(value).is_integer() else value
    if isinstance(value, str):
        m = _NUM_RE.search(value)
        if m:
            f = float(m.group(0))
            return int(f) if f.is_integer() else f
    return None


def _numbers(text):
    """All numbers in a string like '{{1,2},{3,4}}'."""
    if not isinstance(text, str):
        return []
    out = []
    for tok in _NUM_RE.findall(text):
        f = float(tok)
        out.append(int(f) if f.is_integer() else f)
    return out


def _rect(value):
    """(x, y, w, h) from a rect value in any carried shape:
    '{{x,y},{w,h}}' string, {x,y,w,h} / {x,y,width,height}
    dict, or a 4-element sequence. None when unparseable."""
    if value is None:
        return None
    if isinstance(value, str):
        nums = _numbers(value)
        if len(nums) >= 4:
            return tuple(nums[:4])
        return None
    if isinstance(value, dict):
        x = _num(value.get("x"))
        y = _num(value.get("y"))
        w = _num(value.get("w", value.get("width")))
        h = _num(value.get("h", value.get("height")))
        if None not in (x, y, w, h):
            return (x, y, w, h)
        return None
    if isinstance(value, (list, tuple)) and len(value) >= 4:
        vals = [_num(v) for v in value[:4]]
        if None not in vals:
            return tuple(vals)
    return None


def _point(value):
    """(x, y) from '{x,y}', a dict, or a 2-sequence."""
    if value is None:
        return None
    if isinstance(value, str):
        nums = _numbers(value)
        if len(nums) >= 2:
            return (nums[0], nums[1])
        return None
    if isinstance(value, dict):
        x = _num(value.get("x"))
        y = _num(value.get("y"))
        if x is not None and y is not None:
            return (x, y)
        return None
    if isinstance(value, (list, tuple)) and len(value) >= 2:
        x, y = _num(value[0]), _num(value[1])
        if x is not None and y is not None:
            return (x, y)
    return None


def _size(value):
    """(w, h) from '{w,h}', a {w,h}/{width,height} dict, or
    a 2-sequence."""
    if value is None:
        return None
    if isinstance(value, str):
        nums = _numbers(value)
        if len(nums) >= 2:
            return (nums[0], nums[1])
        return None
    if isinstance(value, dict):
        w = _num(value.get("w", value.get("width")))
        h = _num(value.get("h", value.get("height")))
        if w is not None and h is not None:
            return (w, h)
        return None
    if isinstance(value, (list, tuple)) and len(value) >= 2:
        w, h = _num(value[0]), _num(value[1])
        if w is not None and h is not None:
            return (w, h)
    return None


def _truthy(value):
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "y")
    return bool(value)


def _frame(name, x, y, w, h, rotated=False, source_w=None,
           source_h=None, offset_x=None, offset_y=None):
    return {
        "name": str(name),
        "x": x, "y": y, "w": w, "h": h,
        "rotated": bool(rotated),
        "source_w": w if source_w is None else source_w,
        "source_h": h if source_h is None else source_h,
        "offset_x": 0 if offset_x is None else offset_x,
        "offset_y": 0 if offset_y is None else offset_y,
    }


def make_record(fmt, texture=None, page_width=None,
                page_height=None, frames=None, error=None,
                **extra):
    """Assemble one uniform atlas record (see module docstring).

    frame_count / packed_area / rotated_count are derived
    from the frames; a caller that knows a count the frames
    cannot express (Unity GUID-only packing) overrides the
    fields on the returned dict."""
    frames = list(frames or [])
    packed = None
    if frames:
        packed = 0
        for fr in frames:
            if isinstance(fr.get("w"), (int, float)) and \
                    isinstance(fr.get("h"), (int, float)):
                packed += fr["w"] * fr["h"]
            else:
                packed = None
                break
    page_area = None
    if isinstance(page_width, (int, float)) and \
            isinstance(page_height, (int, float)):
        page_area = page_width * page_height
    record = {
        "format": fmt,
        "texture": texture,
        "page_width": page_width,
        "page_height": page_height,
        "frames": frames,
        "frame_count": len(frames),
        "packed_area": packed,
        "page_area": page_area,
        "rotated_count": sum(1 for fr in frames if fr.get("rotated")),
        "error": error,
    }
    record.update(extra)
    return record


def _error_record(fmt, message, **extra):
    return make_record(fmt, error=message, **extra)


def _as_text(data):
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return data


# ----------------------------------------------------------------
# 1. Cocos plist (atlas + particle)
# ----------------------------------------------------------------

PARTICLE_KEYS = {
    "maxParticles", "emitterType", "particleLifespan",
    "particleLifespanVariance", "startParticleSize",
    "finishParticleSize", "startParticleSizeVariance",
    "finishParticleSizeVariance", "gravityx", "gravityy",
    "gravity", "radialAccel", "radialAccelVariance",
    "tangentialAccel", "tangentialAccelVariance",
    "speed", "speedVariance", "angle", "angleVariance",
    "duration", "sourcePositionx", "sourcePositiony",
    "sourcePosition", "rotationStart", "rotationEnd",
    "emitterMode", "posVarx", "posVary",
}


def _cocos_frame(name, value):
    if not isinstance(value, dict):
        return None
    rect = None
    for key in ("frame", "textureRect", "spriteFrame", "rect"):
        rect = _rect(value.get(key))
        if rect is not None:
            break
    if rect is None:
        return None
    x, y, w, h = rect
    rotated = False
    for key in ("rotated", "textureRotated", "spriteRotated"):
        if key in value:
            rotated = _truthy(value.get(key))
            break
    offset = None
    for key in ("offset", "spriteOffset", "textureOffset"):
        offset = _point(value.get(key))
        if offset is not None:
            break
    source = None
    for key in ("sourceSize", "spriteSourceSize", "spriteSize"):
        source = _size(value.get(key))
        if source is not None:
            break
    color_rect = None
    for key in ("sourceColorRect", "spriteColorRect"):
        color_rect = _rect(value.get(key))
        if color_rect is not None:
            break
    if offset is None and color_rect is not None:
        offset = (color_rect[0], color_rect[1])
    if source is None and color_rect is not None:
        source = (color_rect[2], color_rect[3])
    return _frame(name, x, y, w, h, rotated=rotated,
                  source_w=source[0] if source else None,
                  source_h=source[1] if source else None,
                  offset_x=offset[0] if offset else None,
                  offset_y=offset[1] if offset else None)


def _particle_record(doc):
    """Particle facts from a Cocos particle plist dict."""
    def val(*keys):
        for key in keys:
            if key in doc:
                return _num(doc.get(key))
        return None

    gravity = _point(doc.get("gravity"))
    gx = val("gravityx", "gravityX")
    gy = val("gravityy", "gravityY")
    if gravity is not None:
        gx, gy = gravity
    particle = {
        "max_particles": val("maxParticles"),
        "lifespan": val("particleLifespan"),
        "lifespan_variance": val("particleLifespanVariance"),
        "duration": val("duration"),
        "emitter_type": val("emitterType", "emitterMode"),
        "start_size": val("startParticleSize"),
        "end_size": val("finishParticleSize"),
        "angle": val("angle"),
        "speed": val("speed"),
        "gravity_x": gx,
        "gravity_y": gy,
        "gravity": {"x": gx, "y": gy},
        "radial_accel": val("radialAccel"),
        "tangential_accel": val("tangentialAccel"),
        "has_radial_accel": "radialAccel" in doc,
        "has_tangential_accel": "tangentialAccel" in doc,
    }
    return {"format": "cocos-particle-plist",
            "particle": particle, "error": None}


def is_particle_plist(doc):
    if not isinstance(doc, dict) or "frames" in doc:
        return False
    hits = PARTICLE_KEYS.intersection(doc.keys())
    return "maxParticles" in doc or len(hits) >= 3


def parse_cocos_plist(data):
    """Parse a Cocos plist (XML or binary bytes).

    Returns a uniform atlas record, a particle record
    ({format: "cocos-particle-plist", particle: {...}}) for
    particle plists, or an error record."""
    try:
        doc = plistlib.loads(data)
    except Exception as exc:  # plistlib raises several types
        return _error_record("cocos-plist", f"plist parse failed: {exc}")
    if not isinstance(doc, dict):
        return _error_record("cocos-plist",
                             "plist root is not a dictionary")
    if is_particle_plist(doc):
        return _particle_record(doc)
    frames_doc = doc.get("frames")
    if not isinstance(frames_doc, dict):
        return _error_record(
            "cocos-plist",
            "plist has no 'frames' dictionary and is not a "
            "recognised particle plist")
    frames = []
    for name in sorted(frames_doc):
        fr = _cocos_frame(name, frames_doc[name])
        if fr is not None:
            frames.append(fr)
    meta = doc.get("metadata") or doc.get("meta") or {}
    if not isinstance(meta, dict):
        meta = {}
    size = _size(meta.get("size")) or _size(meta.get("textureSize"))
    texture = meta.get("realTextureFileName") or \
        meta.get("textureFileName")
    return make_record(
        "cocos-plist",
        texture=str(texture) if texture else None,
        page_width=size[0] if size else None,
        page_height=size[1] if size else None,
        frames=frames)


# ----------------------------------------------------------------
# 2. TexturePacker JSON / Phaser JSON
# ----------------------------------------------------------------

def _frame_rect_ok(value):
    """A frame entry is atlas-shaped only when it carries a
    'frame' rect with numeric x/y/w/h. This is the guard that
    keeps Lottie / Spine / arbitrary JSON out of the atlas
    classification."""
    if not isinstance(value, dict):
        return False
    rect = value.get("frame")
    if not isinstance(rect, dict):
        return False
    return all(_num(rect.get(k)) is not None
               for k in ("x", "y", "w", "h"))


def _tp_frame(name, entry):
    rect = _rect(entry.get("frame"))
    if rect is None:
        return None
    x, y, w, h = rect
    sss = entry.get("spriteSourceSize")
    offset = _point({"x": sss.get("x"), "y": sss.get("y")}) \
        if isinstance(sss, dict) else None
    source = _size(entry.get("sourceSize"))
    return _frame(name, x, y, w, h,
                  rotated=_truthy(entry.get("rotated", False)),
                  source_w=source[0] if source else None,
                  source_h=source[1] if source else None,
                  offset_x=offset[0] if offset else None,
                  offset_y=offset[1] if offset else None)


def _tp_frames_from(frames_doc):
    frames = []
    if isinstance(frames_doc, dict):
        for name in sorted(frames_doc):
            entry = frames_doc[name]
            if _frame_rect_ok(entry):
                fr = _tp_frame(name, entry)
                if fr is not None:
                    frames.append(fr)
    elif isinstance(frames_doc, list):
        for entry in frames_doc:
            if not isinstance(entry, dict) or \
                    not _frame_rect_ok(entry):
                continue
            name = entry.get("filename") or entry.get("key") or \
                entry.get("name")
            if not name:
                continue
            fr = _tp_frame(str(name), entry)
            if fr is not None:
                frames.append(fr)
    return frames


def classify_json_atlas(doc):
    """Classify a parsed JSON document as an atlas, or None.

    Returns "phaser-json", "texturepacker-json-hash" or
    "texturepacker-json-array". The classification is purely
    structural: a top-level "textures" list of pages with
    frame-shaped entries, or a top-level "frames" dict/list
    whose entries carry frame rects. A meta.app mentioning
    TexturePacker is supporting evidence, never sufficient
    on its own."""
    if not isinstance(doc, dict):
        return None
    textures = doc.get("textures")
    if isinstance(textures, list) and textures:
        ok = True
        for page in textures:
            if not isinstance(page, dict):
                ok = False
                break
            page_frames = _tp_frames_from(page.get("frames"))
            if not page_frames:
                ok = False
                break
        if ok:
            return "phaser-json"
    frames_doc = doc.get("frames")
    if isinstance(frames_doc, dict) and frames_doc:
        values = list(frames_doc.values())
        if values and all(_frame_rect_ok(v) for v in values):
            return "texturepacker-json-hash"
    if isinstance(frames_doc, list) and frames_doc:
        shaped = [e for e in frames_doc if _frame_rect_ok(e)]
        named = [e for e in shaped
                 if e.get("filename") or e.get("key")
                 or e.get("name")]
        if shaped and len(named) == len(shaped) and \
                len(shaped) == len(frames_doc):
            return "texturepacker-json-array"
    return None


def parse_texturepacker_json(doc):
    """Parse a classified TexturePacker / Phaser JSON doc.

    Returns a list of uniform records (one per texture page
    for the Phaser variant, exactly one otherwise), or a
    single error record when the doc is not atlas-shaped."""
    kind = classify_json_atlas(doc)
    if kind is None:
        return [_error_record(
            "texturepacker-json",
            "JSON structure is not a recognised TexturePacker "
            "or Phaser atlas (no frame rects with x/y/w/h)")]
    records = []
    if kind == "phaser-json":
        for page in doc.get("textures") or []:
            size = _size(page.get("size"))
            records.append(make_record(
                "phaser-json",
                texture=page.get("image"),
                page_width=size[0] if size else None,
                page_height=size[1] if size else None,
                frames=_tp_frames_from(page.get("frames"))))
        return records
    meta = doc.get("meta") or {}
    if not isinstance(meta, dict):
        meta = {}
    size = _size(meta.get("size"))
    return [make_record(
        kind,
        texture=meta.get("image"),
        page_width=size[0] if size else None,
        page_height=size[1] if size else None,
        frames=_tp_frames_from(doc.get("frames")))]


# ----------------------------------------------------------------
# 3. Starling XML / TexturePacker XML
# ----------------------------------------------------------------

def _attr_num(elem, name):
    raw = elem.get(name)
    return _num(raw) if raw is not None else None


def parse_xml_atlas(data):
    """Parse a Starling or TexturePacker XML atlas (bytes or
    text). The child element tag decides the dialect:
    SubTexture is Starling, sprite is TexturePacker XML."""
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        return _error_record("xml-atlas", f"XML parse failed: {exc}")
    if root.tag != "TextureAtlas":
        return _error_record(
            "xml-atlas",
            f"root element is {root.tag!r}, not TextureAtlas")
    texture = root.get("imagePath")
    page_w = _attr_num(root, "width")
    page_h = _attr_num(root, "height")
    children = list(root)
    tags = {child.tag for child in children}
    frames = []
    if "SubTexture" in tags:
        fmt = "starling-xml"
        for child in children:
            if child.tag != "SubTexture":
                continue
            name = child.get("name")
            x, y = _attr_num(child, "x"), _attr_num(child, "y")
            w = _attr_num(child, "width")
            h = _attr_num(child, "height")
            if name is None or None in (x, y, w, h):
                continue
            frame_w = _attr_num(child, "frameWidth")
            frame_h = _attr_num(child, "frameHeight")
            frame_x = _attr_num(child, "frameX")
            frame_y = _attr_num(child, "frameY")
            # Starling frameX/frameY are the (usually negative)
            # position of the full frame relative to the trimmed
            # sprite; the trim offset inside the source frame is
            # their negation.
            frames.append(_frame(
                name, x, y, w, h,
                rotated=_truthy(child.get("rotated", "false")),
                source_w=frame_w, source_h=frame_h,
                offset_x=-frame_x if frame_x is not None else None,
                offset_y=-frame_y if frame_y is not None else None))
    elif "sprite" in tags:
        fmt = "texturepacker-xml"
        for child in children:
            if child.tag != "sprite":
                continue
            name = child.get("n")
            x, y = _attr_num(child, "x"), _attr_num(child, "y")
            w, h = _attr_num(child, "w"), _attr_num(child, "h")
            if name is None or None in (x, y, w, h):
                continue
            frames.append(_frame(
                name, x, y, w, h,
                rotated=_truthy(child.get("r", "false")),
                source_w=_attr_num(child, "oW"),
                source_h=_attr_num(child, "oH"),
                offset_x=_attr_num(child, "oX"),
                offset_y=_attr_num(child, "oY")))
    else:
        return _error_record(
            "xml-atlas",
            "TextureAtlas has neither SubTexture (Starling) "
            "nor sprite (TexturePacker XML) children")
    return make_record(fmt, texture=texture, page_width=page_w,
                       page_height=page_h, frames=frames)


# ----------------------------------------------------------------
# 4. libGDX .atlas / .pack text
# ----------------------------------------------------------------

_PAGE_KEYS = ("size:", "format:", "filter:", "repeat:", "pma:")


def _gdx_pair(value):
    nums = _numbers(value)
    if len(nums) >= 2:
        return (nums[0], nums[1])
    return None


def _gdx_region_frame(name, props):
    x = y = w = h = None
    if "bounds" in props:
        rect = _rect(props["bounds"])
        if rect is not None:
            x, y, w, h = rect
    if x is None and "xy" in props and "size" in props:
        xy = _gdx_pair(props["xy"])
        sz = _gdx_pair(props["size"])
        if xy and sz:
            x, y, w, h = xy[0], xy[1], sz[0], sz[1]
    if x is None:
        return None
    rotate_raw = str(props.get("rotate", "false")).strip().lower()
    rotated = rotate_raw in ("true", "90")
    source = None
    if "orig" in props:
        source = _gdx_pair(props["orig"])
    offset = None
    if "offset" in props:
        offset = _gdx_pair(props["offset"])
    if "offsets" in props:
        nums = _numbers(props["offsets"])
        if len(nums) >= 2:
            offset = (nums[0], nums[1])
        if source is None and len(nums) >= 4:
            source = (nums[2], nums[3])
    return _frame(name, x, y, w, h, rotated=rotated,
                  source_w=source[0] if source else None,
                  source_h=source[1] if source else None,
                  offset_x=offset[0] if offset else None,
                  offset_y=offset[1] if offset else None)


def parse_libgdx_atlas(text):
    """Parse libGDX .atlas/.pack text into one record per page.

    Page headers are bare lines (image name, then size: /
    format: / filter: / repeat: lines); region blocks are a
    bare name line followed by indented property lines. A
    bare line whose next non-blank line is a page key starts
    a new page; a bare line whose next line is indented
    starts a region."""
    text = _as_text(text)
    lines = text.splitlines()
    pages = []
    page = None
    region = None

    def _next_content(idx):
        for j in range(idx + 1, len(lines)):
            if lines[j].strip():
                return lines[j]
        return None

    for idx, raw in enumerate(lines):
        if not raw.strip():
            region = None
            continue
        stripped = raw.strip()
        if raw[0] in (" ", "\t"):
            if region is not None and ":" in stripped:
                key, _, value = stripped.partition(":")
                region["props"][key.strip()] = value.strip()
            continue
        if stripped.startswith(_PAGE_KEYS) and page is not None \
                and region is None:
            key, _, value = stripped.partition(":")
            if key.strip() == "size":
                size = _gdx_pair(value)
                if size:
                    page["width"], page["height"] = size
            continue
        nxt = _next_content(idx)
        is_page = nxt is not None and \
            nxt.strip().startswith(_PAGE_KEYS)
        if is_page:
            page = {"texture": stripped, "width": None,
                    "height": None, "regions": []}
            pages.append(page)
            region = None
        else:
            if page is None:
                page = {"texture": None, "width": None,
                        "height": None, "regions": []}
                pages.append(page)
            region = {"name": stripped, "props": {}}
            page["regions"].append(region)
    records = []
    for pg in pages:
        frames = []
        for reg in pg["regions"]:
            fr = _gdx_region_frame(reg["name"], reg["props"])
            if fr is not None:
                frames.append(fr)
        records.append(make_record(
            "libgdx-atlas", texture=pg["texture"],
            page_width=pg["width"], page_height=pg["height"],
            frames=frames))
    if not records:
        return [_error_record("libgdx-atlas",
                              "no atlas pages found in text")]
    return records


# ----------------------------------------------------------------
# 5. Godot .tres AtlasTexture
# ----------------------------------------------------------------

_EXT_RESOURCE_RE = re.compile(r"\[ext_resource[^\]]*\]")
_PATH_RE = re.compile(r'path\s*=\s*"([^"]+)"')
_ID_RE = re.compile(r'id\s*=\s*"([^"]+)"')
_ATLAS_REF_RE = re.compile(r'atlas\s*=\s*ExtResource\("([^"]+)"\)')
_REGION_RE = re.compile(r"region\s*=\s*Rect2\(([^)]*)\)")
_MARGIN_RE = re.compile(r"margin\s*=\s*Rect2\(([^)]*)\)")


def parse_godot_tres(text, resource_path=None):
    """Parse a standalone Godot .tres AtlasTexture resource.

    The frame is the resource's single region; its name comes
    from the resource's own path when the caller passes one,
    else "region". The page size is not stated in a .tres
    file, so page_width/page_height stay null. AtlasTexture
    blocks embedded in .tscn scene text are not parsed here."""
    text = _as_text(text)
    if "AtlasTexture" not in text:
        return _error_record(
            "godot-atlas-texture",
            "resource does not declare an AtlasTexture")
    m = _REGION_RE.search(text)
    if not m:
        return _error_record(
            "godot-atlas-texture",
            "AtlasTexture resource has no region Rect2")
    nums = _numbers(m.group(1))
    if len(nums) < 4:
        return _error_record(
            "godot-atlas-texture",
            "region Rect2 does not carry x, y, w, h")
    x, y, w, h = nums[:4]
    margin = _MARGIN_RE.search(text)
    off_x = off_y = 0
    if margin:
        mnums = _numbers(margin.group(1))
        if len(mnums) >= 2:
            off_x, off_y = mnums[0], mnums[1]
    texture = None
    paths = {}
    for block in _EXT_RESOURCE_RE.findall(text):
        pm, im = _PATH_RE.search(block), _ID_RE.search(block)
        if pm and im:
            paths[im.group(1)] = pm.group(1)
    ref = _ATLAS_REF_RE.search(text)
    if ref and ref.group(1) in paths:
        texture = paths[ref.group(1)].rsplit("/", 1)[-1]
    elif paths:
        texture = next(iter(paths.values())).rsplit("/", 1)[-1]
    if resource_path:
        base = str(resource_path).replace("\\", "/") \
            .rsplit("/", 1)[-1]
        name = base.rsplit(".", 1)[0] if "." in base else base
    else:
        name = "region"
    frame = _frame(name, x, y, w, h, rotated=False,
                   offset_x=off_x, offset_y=off_y)
    return make_record("godot-atlas-texture", texture=texture,
                       frames=[frame])


# ----------------------------------------------------------------
# 6. Unity .spriteatlas (text YAML, GUID-only fidelity)
# ----------------------------------------------------------------

def _yaml_list_count(lines, start_idx, key_indent):
    """Count '- ' items in the YAML list starting after
    lines[start_idx], stopping at the first non-blank line
    dedented to (or above) the key's indent that is not a
    list item."""
    count = 0
    for raw in lines[start_idx + 1:]:
        if not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip())
        stripped = raw.strip()
        if stripped.startswith("- ") or stripped == "-":
            if indent >= key_indent:
                count += 1
                continue
            break
        if indent <= key_indent:
            break
        # Deeper-indented continuation of a list item: ignore.
    return count


def parse_unity_spriteatlas(text):
    """Parse a Unity .spriteatlas text-YAML file.

    Text YAML references packed sprites by GUID only, so
    frame names and rects are not recoverable from this file:
    frames is empty, frame_count is the number of packed
    sprite entries, and names_recoverable is False. Nothing
    is invented to fill the gap."""
    text = _as_text(text)
    lines = text.splitlines()
    name = None
    packed_count = 0
    render_key_count = None
    for idx, raw in enumerate(lines):
        stripped = raw.strip()
        if name is None and stripped.startswith("m_Name:"):
            value = stripped.split(":", 1)[1].strip().strip('"')
            if value:
                name = value
        if stripped.startswith("m_PackedSprites:"):
            indent = len(raw) - len(raw.lstrip())
            rest = stripped.split(":", 1)[1].strip()
            if rest == "[]":
                packed_count = 0
            else:
                packed_count = _yaml_list_count(lines, idx, indent)
        if stripped.startswith("m_PackedAtlasRenderDataKeys:"):
            indent = len(raw) - len(raw.lstrip())
            rest = stripped.split(":", 1)[1].strip()
            render_key_count = 0 if rest == "[]" else \
                _yaml_list_count(lines, idx, indent)
    record = make_record(
        "unity-spriteatlas",
        frames=[],
        names_recoverable=False,
        packed_sprite_count=packed_count,
        render_data_key_count=render_key_count,
        note=("Packed sprites are referenced by GUID in text "
              "YAML; frame names and rects are not recoverable "
              "from the .spriteatlas file alone."))
    record["frame_count"] = packed_count
    record["packed_area"] = None
    if name:
        record["atlas_name"] = name
    return record
