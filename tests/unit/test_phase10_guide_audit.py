"""Evolution Phase 10 — the guide-vs-code audit, encoded.

The Phase 0 audit deferred the full check; Phase 10 ran it
once by hand (see the Phase 10 record in
NAR_IMPLEMENTATION_PLAN.md) and this test keeps the durable
parts enforced:

  * every (references/…)/(scripts/…) link target named in
    SKILL.md or any guide exists;
  * every nar-*.py / nar-*.sh filename mentioned in SKILL.md
    or any guide exists in scripts/;
  * every --flag written on a line that names a nar script
    is a flag that script actually defines (external-tool
    flags live on lines naming the external tool, so they
    are out of scope here by construction);
  * every backticked `nar <verb>` in SKILL.md / guides is a
    verb the dispatcher really has;
  * SKILL.md frontmatter parses and its version matches the
    library version; plugin.json parses and matches too.
"""
import importlib.util
import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

DOCS = [os.path.join(ROOT, "SKILL.md")] + sorted(
    os.path.join(ROOT, "references", name)
    for name in os.listdir(os.path.join(ROOT, "references"))
    if name.endswith(".md"))


def _text(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _script_flags():
    flags = {}
    scripts_dir = os.path.join(ROOT, "scripts")
    for name in os.listdir(scripts_dir):
        if name.endswith((".py", ".sh")):
            text = _text(os.path.join(scripts_dir, name))
            flags[name] = (set(re.findall(r'"(--[a-z][a-z0-9-]*)"', text))
                           | set(re.findall(r"'(--[a-z][a-z0-9-]*)'", text)))
    return flags


def test_guide_link_targets_exist():
    missing = []
    for path in DOCS:
        for target in re.findall(r"\(((?:references|scripts)/[^)\s]+)\)",
                                 _text(path)):
            if not os.path.isfile(os.path.join(ROOT, target)):
                missing.append((os.path.basename(path), target))
    assert missing == []


def test_guide_script_filenames_exist():
    missing = []
    for path in DOCS:
        for name in set(re.findall(r"\b(nar-[a-z0-9-]+\.(?:py|sh))\b",
                                   _text(path))):
            if not os.path.isfile(os.path.join(ROOT, "scripts", name)):
                missing.append((os.path.basename(path), name))
    assert missing == []


def test_guide_flags_attributed_to_nar_scripts_are_real():
    flags = _script_flags()
    bad = []
    for path in DOCS:
        for line in _text(path).splitlines():
            for script in re.findall(r"(nar-[a-z0-9-]+\.(?:py|sh))", line):
                for tok in re.findall(r"--[a-z][a-z0-9-]*", line):
                    if tok != "--help" and tok not in flags.get(script, set()):
                        bad.append((os.path.basename(path), script, tok))
    assert bad == []


def test_guide_nar_verbs_are_real():
    spec = importlib.util.spec_from_file_location(
        "nar_cli", os.path.join(ROOT, "scripts", "nar.py"))
    nar = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(nar)
    verbs = set(nar.COMMANDS) | {"case", "version"}
    bad = []
    for path in DOCS:
        for verb in set(re.findall(r"`nar ([a-z][a-z-]*)", _text(path))):
            if verb not in verbs:
                bad.append((os.path.basename(path), verb))
    assert bad == []


def test_skill_frontmatter_and_plugin_versions():
    text = _text(os.path.join(ROOT, "SKILL.md"))
    assert text.startswith("---\n")
    front = text.split("---\n", 2)[1]
    assert re.search(r"^name:\s*nar\s*$", front, re.M)
    version = re.search(r'version:\s*"([^"]+)"', front).group(1)
    import narlib
    assert version == narlib.__version__
    plugin = json.loads(_text(os.path.join(
        ROOT, ".claude-plugin", "plugin.json")))
    assert plugin["version"] == version
    assert plugin["name"]
