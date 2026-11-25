"""Part grouping and composition inference (Part 4, atlas side).

Sprite atlases pack the parts of composite objects — a
vehicle's body, wheels and springs, a character's torso,
head and limbs, a UI kit's buttons and panels — as sibling
frames with systematic names. This module groups frames by
their shared naming prefix, classifies each part with a
generic English part vocabulary, and emits a composition
record per group: what object the frames appear to compose,
which part each frame plays, and the naming pattern they
follow.

Everything here is name-based inference and is labelled as
such (classification_label / driver_label: "inferred"). An
atlas carries no attachment or driver data, so atlas-side
records always carry attachment_points=[] and
driver="unknown" with a driver_reason; the fuller driver
classification belongs to the animation side, whose records
share schemas/composition.schema.json.

The vocabulary is generic part terminology only — no
target-specific names appear anywhere in this module.

Part of NAR (Nirous Android Reversing).
MIT License. See LICENSE in the repo root.
"""
import re

# ----------------------------------------------------------------
# Part-role lexicon (generic English part vocabulary)
# ----------------------------------------------------------------

ROLE_LEXICON = {
    "body": {
        "chassis", "body", "hull", "torso", "cabin", "fuselage",
        "bodies", "torsos", "cabins",
    },
    "wheel": {
        "wheel", "wheels", "tire", "tires", "tyre", "tyres",
    },
    "suspension": {
        "suspension", "spring", "springs", "shock", "shocks",
        "strut", "struts", "axle", "axles",
    },
    "limb": {
        "arm", "arms", "leg", "legs", "hand", "hands",
        "foot", "feet", "finger", "fingers", "paw", "paws",
    },
    "head": {
        "head", "heads", "face", "faces",
    },
    "appendage": {
        "wing", "wings", "tail", "tails", "turret", "turrets",
        "antenna", "antennas", "antennae", "propeller",
        "propellers", "fin", "fins",
    },
    "ui": {
        "button", "buttons", "btn", "icon", "icons", "bg",
        "background", "backgrounds", "panel", "panels",
        "border", "borders", "banner", "banners", "bar",
        "bars", "hud", "menu", "menus", "cursor", "slider",
        "sliders", "tab", "tabs",
    },
    "environment": {
        "tree", "trees", "rock", "rocks", "ground", "cloud",
        "clouds", "building", "buildings", "mountain",
        "mountains", "grass", "bush", "bushes", "flower",
        "flowers", "water", "snow", "sand", "stone", "stones",
    },
}

# Bare "frame" is deliberately absent: it is ambiguous between
# a body part, an animation frame and a UI border, so it must
# never drive a classification on its own.
TOKEN_TO_ROLE = {}
for _role, _tokens in ROLE_LEXICON.items():
    for _tok in _tokens:
        TOKEN_TO_ROLE.setdefault(_tok, _role)

PART_TOKENS = set(TOKEN_TO_ROLE)

_SPLIT_RE = re.compile(r"[-_/\s.]+")
_SIZE_TOKEN_RE = re.compile(r"^\d+(?:\.\d+)?x$")
_IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".webp", ".gif",
               ".bmp", ".tga", ".dds", ".astc", ".pvr")


def strip_extension(name):
    low = name.lower()
    for ext in _IMAGE_EXTS:
        if low.endswith(ext):
            return name[:-len(ext)]
    return name


def tokenise(name):
    """Tokens of a frame name: extension stripped, split on
    '-', '_', '/', ' ', '.', lowercased, empties dropped."""
    base = strip_extension(str(name))
    return [t for t in _SPLIT_RE.split(base.lower()) if t]


def _is_index_token(tok):
    return tok.isdigit() or bool(_SIZE_TOKEN_RE.match(tok))


def _core_tokens(name):
    """Tokens with trailing pure-numeric and trailing size
    tokens (e.g. "2x") dropped, repeatedly."""
    tokens = tokenise(name)
    while tokens and _is_index_token(tokens[-1]):
        tokens.pop()
    return tokens


def group_key_for(name):
    """The shared prefix path one frame name contributes.

    When a part-vocabulary token appears at position >= 1,
    the key is everything before the first such token (the
    part word and any qualifiers after it, e.g. a direction
    word, belong to the part, not the object). Otherwise the
    key is all but the last meaningful token. Returns
    (key_string, key_tokens)."""
    tokens = _core_tokens(name)
    if not tokens:
        return "", []
    for i in range(1, len(tokens)):
        if tokens[i] in PART_TOKENS:
            return "-".join(tokens[:i]), tokens[:i]
    if len(tokens) >= 2:
        return "-".join(tokens[:-1]), tokens[:-1]
    return tokens[0], list(tokens)


def group_frames(frames):
    """Group atlas frames by shared naming prefix.

    ``frames`` is a list of frame dicts (each with "name") or
    plain name strings. Returns a list of groups, each
    {key, frames, names}, holding only groups with >= 2
    frames, sorted by key. A frame whose name yields no key
    is left ungrouped."""
    buckets = {}
    for item in frames or []:
        if isinstance(item, dict):
            name = item.get("name")
            record = item
        else:
            name = item
            record = {"name": item}
        if not name:
            continue
        key, _ = group_key_for(str(name))
        if not key:
            continue
        bucket = buckets.setdefault(
            key, {"key": key, "frames": [], "names": []})
        bucket["frames"].append(record)
        bucket["names"].append(str(name))
    groups = [g for g in buckets.values() if len(g["frames"]) >= 2]
    groups.sort(key=lambda g: g["key"])
    return groups


def role_for_name(name, key_tokens=None):
    """The part role of one frame name: the role of the first
    part-vocabulary token at or after the group-key prefix,
    or "unknown" when no token carries a role."""
    tokens = _core_tokens(name)
    start = len(key_tokens) if key_tokens else 0
    for tok in tokens[start:]:
        role = TOKEN_TO_ROLE.get(tok)
        if role:
            return role
    if key_tokens:
        for tok in tokens:
            role = TOKEN_TO_ROLE.get(tok)
            if role:
                return role
    return "unknown"


def classify_group(group):
    """Classify one group (from group_frames, or a bare list
    of names) as vehicle / character / ui / environment /
    unknown. Name-based inference only:

    - vehicle: a body-like part AND a wheel-like part;
    - character: a body/torso/head-like part AND a limb part;
    - ui: all or most frames carry UI part tokens;
    - environment: environment part tokens dominate;
    - otherwise unknown."""
    if isinstance(group, dict):
        names = group.get("names") or \
            [f.get("name") for f in group.get("frames", [])]
        key = group.get("key") or ""
    else:
        names = list(group or [])
        key = ""
    names = [n for n in names if n]
    if not names:
        return "unknown"
    key_tokens = tokenise(key) if key else None
    roles = [role_for_name(n, key_tokens) for n in names]
    role_set = set(roles)
    total = len(roles)
    if "body" in role_set and "wheel" in role_set:
        return "vehicle"
    if role_set.intersection(("body", "head")) and \
            "limb" in role_set:
        return "character"
    ui_count = roles.count("ui")
    if ui_count == total or ui_count * 2 > total:
        return "ui"
    env_count = roles.count("environment")
    if env_count * 2 >= total and env_count > 0:
        return "environment"
    return "unknown"


def _naming_pattern(group):
    names = group.get("names") or []
    dashes = sum(n.count("-") for n in names)
    underscores = sum(n.count("_") for n in names)
    sep = "_" if underscores > dashes else "-"
    pattern = f"<group>{sep}<part>"
    for name in names:
        tokens = tokenise(name)
        core = _core_tokens(name)
        if len(tokens) > len(core):
            pattern += f"{sep}<index>"
            break
    return pattern


def composition_record(group):
    """One composition record for a group (see module
    docstring). Validates against
    schemas/composition.schema.json; the atlas side always
    reports driver "unknown" because an atlas carries no
    skeleton, physics or driver data."""
    key = group.get("key") or ""
    key_tokens = tokenise(key) if key else []
    names = group.get("names") or \
        [f.get("name") for f in group.get("frames", [])]
    parts = [{"name": n, "role": role_for_name(n, key_tokens)}
             for n in names]
    classification = classify_group(group)
    return {
        "object": key,
        "classification": classification,
        "classification_label": "inferred",
        "parts": parts,
        "naming_pattern": _naming_pattern(group),
        "attachment_points": [],
        "driver": "unknown",
        "driver_label": "inferred",
        "driver_reason": (
            "atlas frame names only; the atlas carries no "
            "skeleton, physics or driver data, so how the "
            "parts are driven cannot be determined from the "
            "atlas alone"),
        "evidence": [
            f"{len(names)} atlas frames share the naming "
            f"prefix {key!r}",
            "part roles assigned from frame-name part "
            "vocabulary; classification inferred from the "
            "combination of roles present",
        ],
        "confidence": "low",
    }


def compositions_from_frames(frames):
    """All composition records for one flat frame list."""
    return [composition_record(g) for g in group_frames(frames)]
