"""Real YAML-parser validation for the skill metadata (2.5.2 W1).

Until 2.5.2 the only validation of ``skill.yaml`` and of the
``SKILL.md`` frontmatter was regex-based (version grabs in
``test_docs_consistency.py`` and ``startswith`` + ``re.search``
in ``test_phase10_guide_audit.py``). That is how invalid YAML
shipped unnoticed: both files carried an unquoted colon inside
a plain scalar (``title: NAR: Nirous Android Reversing`` and
the ``description:`` value after "CLI tools"), and PyYAML
``safe_load`` rejects both with "mapping values are not
allowed here".

These tests parse both files with a real YAML parser and pin
the exact metadata text, so quoting regressions fail loudly.
PyYAML is a test-only dependency (declared in the ``test``
and ``dev`` extras in ``pyproject.toml``); the shipped tools
stay stdlib-only. When PyYAML is not importable the whole
module SKIPs with a stated reason — it never fake-passes.
"""
import os
import re

import pytest

try:
    import yaml
except ImportError:  # pragma: no cover - depends on the env
    yaml = None

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

SKIP_REASON = (
    "PyYAML is not installed, so real YAML parsing cannot run; "
    "install the test dependencies (pip install pyyaml, or the "
    "pyproject 'test'/'dev' extras) to enable these tests"
)

pytestmark = pytest.mark.skipif(yaml is None, reason=SKIP_REASON)

EXPECTED_SKILL_TITLE = "NAR: Nirous Android Reversing"
EXPECTED_SKILL_DESCRIPTION = (
    "Reverse engineer any Android APK or AAB (apps and games) "
    "with CLI tools: triage, manifest and resources, DEX/smali, "
    "jadx decompile, native/JNI, game engines, Unity IL2CPP "
    "deep analysis, Flutter/Dart, app bundles, network "
    "traffic, Frida scripts, signatures, version compare, "
    "feature maps, and legacy (Android 4.x-7) and modern "
    "(Android 14/15/16) analysis."
)
EXPECTED_FRONTMATTER_DESCRIPTION = (
    "Reverse engineer any Android APK or AAB (apps and games) "
    "with CLI tools: triage and inventory, manifest and "
    "resources, DEX/smali analysis, jadx decompilation, native "
    "libraries and JNI, game engines (Unity/Unreal/Godot), "
    "Unity IL2CPP deep analysis, Flutter/Dart, app bundles, "
    "network traffic, Frida scripts, signatures, version "
    "comparison, feature maps, and legacy (Android 4.x-7) and "
    "modern (Android 14/15/16) analysis."
)


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def _skill_yaml():
    return yaml.safe_load(_read("skill.yaml"))


def _frontmatter_text():
    text = _read("SKILL.md")
    assert text.startswith("---\n"), "SKILL.md must open with a --- fence"
    return text.split("---\n", 2)[1]


def _frontmatter():
    return yaml.safe_load(_frontmatter_text())


# --- skill.yaml: real parse, expected keys and types -----------------

def test_skill_yaml_parses_to_a_mapping():
    data = _skill_yaml()
    assert isinstance(data, dict)


def test_skill_yaml_expected_keys_and_types():
    data = _skill_yaml()
    assert isinstance(data["name"], str) and data["name"]
    assert isinstance(data["title"], str) and data["title"]
    assert "version" in data and str(data["version"])
    assert isinstance(data["description"], str)
    assert data["description"].strip(), "description must be non-empty"
    assert isinstance(data["category"], str) and data["category"]
    assert isinstance(data["include_in_prompt"], bool)


def test_skill_yaml_exact_metadata_text_preserved():
    data = _skill_yaml()
    assert data["name"] == "nar"
    assert data["title"] == EXPECTED_SKILL_TITLE
    assert data["description"] == EXPECTED_SKILL_DESCRIPTION
    assert data["category"] == "Work and knowledge"
    assert data["include_in_prompt"] is False


# --- SKILL.md frontmatter: real parse, expected keys and types -------

def test_skill_md_frontmatter_parses_to_a_mapping():
    data = _frontmatter()
    assert isinstance(data, dict)


def test_skill_md_frontmatter_expected_keys_and_types():
    data = _frontmatter()
    assert isinstance(data["name"], str) and data["name"] == "nar"
    assert isinstance(data["description"], str)
    assert data["description"].strip(), "description must be non-empty"
    assert isinstance(data["metadata"], dict)
    version = data["metadata"]["version"]
    assert isinstance(version, str) and version


def test_skill_md_frontmatter_exact_description_preserved():
    data = _frontmatter()
    assert data["description"] == EXPECTED_FRONTMATTER_DESCRIPTION


def test_parsed_versions_agree_with_each_other_and_regex_grabs():
    skill = _skill_yaml()
    front = _frontmatter()
    parsed_version = str(skill["version"])
    assert front["metadata"]["version"] == parsed_version
    # The long-standing regex grabs must keep working unchanged:
    # skill.yaml `^version:\s*(\S+)` and SKILL.md `version:\s*"..."`.
    regex_skill = re.search(
        r"^version:\s*(\S+)", _read("skill.yaml"), re.M).group(1)
    regex_front = re.search(
        r'version:\s*"([^"]+)"', _read("SKILL.md")).group(1)
    assert regex_skill == parsed_version
    assert regex_front == parsed_version


def test_quoted_colon_value_parses_to_exact_text():
    # Positive control for the fix pattern itself: a double-quoted
    # scalar keeps the colon inside the value, word for word.
    data = yaml.safe_load('title: "NAR: Nirous Android Reversing"\n')
    assert data == {"title": EXPECTED_SKILL_TITLE}


# --- malformed YAML: the parser must reject every variant ------------

MALFORMED_YAML = {
    "unquoted_colon_in_title":
        "name: nar\ntitle: NAR: Nirous Android Reversing\n",
    "unquoted_colon_in_description":
        "name: nar\ndescription: Work with CLI tools: triage\n",
    "unclosed_double_quote":
        'name: nar\ntitle: "NAR: Nirous Android Reversing\n',
    "unclosed_single_quote":
        "name: nar\ntitle: 'NAR: Nirous Android Reversing\n",
    "tab_indentation":
        "name: nar\n\ttitle: nar\n",
    "tab_indented_nested_mapping":
        'metadata:\n\tversion: "2.5.1"\n',
}


@pytest.mark.parametrize("text", MALFORMED_YAML.values(),
                         ids=MALFORMED_YAML.keys())
def test_malformed_yaml_fails_parsing(text):
    with pytest.raises(yaml.YAMLError):
        yaml.safe_load(text)


MALFORMED_FRONTMATTER = {
    # The exact 2.5.1 SKILL.md bug shape: unquoted colon in the
    # description plain scalar.
    "frontmatter_unquoted_colon":
        "name: nar\ndescription: Work with CLI tools: triage\n"
        "metadata:\n  version: \"2.5.1\"\n",
    "frontmatter_unclosed_quote":
        'name: nar\ndescription: "Work with CLI tools: triage\n'
        "metadata:\n  version: \"2.5.1\"\n",
    "frontmatter_tab_indentation":
        "name: nar\nmetadata:\n\tversion: \"2.5.1\"\n",
}


@pytest.mark.parametrize("text", MALFORMED_FRONTMATTER.values(),
                         ids=MALFORMED_FRONTMATTER.keys())
def test_malformed_frontmatter_fails_parsing(text):
    with pytest.raises(yaml.YAMLError):
        yaml.safe_load(text)


def test_duplicate_key_rejected_by_strict_loader():
    # Stock PyYAML safe_load accepts duplicate keys (last value
    # wins), so the duplicate-key regression is asserted with a
    # duplicate-rejecting SafeLoader: under a strict parser the
    # document must fail.
    class StrictLoader(yaml.SafeLoader):
        pass

    def _construct_mapping(loader, node, deep=False):
        seen = set()
        for key_node, _value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in seen:
                raise yaml.YAMLError("duplicate key: %r" % (key,))
            seen.add(key)
        return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)

    StrictLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        _construct_mapping)
    with pytest.raises(yaml.YAMLError):
        yaml.load("name: nar\nname: other\n", Loader=StrictLoader)
