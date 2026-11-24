"""Unit tests: documentation/tree consistency guards.

Evolution Phase 1. The README "Repo structure" block once
described the 1.x layout while the tree had moved on; these
tests make that class of drift fail loudly:

- every file under scripts/, scripts/narlib/, scripts/frida/,
  references/ and schemas/ is named in the README structure
  block, and the block's stated guide count matches the tree;
- every references/ or scripts/ link target in SKILL.md
  exists on disk;
- every version-bearing file agrees on a single version,
  and a planted mismatch in a temp copy is detected.
"""
import json
import os
import re
import shutil
import sys
import tempfile
import unittest

try:
    import yaml
except ImportError:  # PyYAML is a test-only dependency (2.5.2 W1)
    yaml = None

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _read(root, rel):
    with open(os.path.join(root, rel), encoding="utf-8") as fh:
        return fh.read()


def _structure_block(readme_text):
    start = readme_text.index("## Repo structure")
    end = readme_text.index("\n## ", start + 1)
    return readme_text[start:end]


def collect_versions(root):
    """Map of version-bearing location -> version string."""
    found = {}

    def grab(rel, pattern, label=None):
        m = re.search(pattern, _read(root, rel), re.M)
        if m:
            found[label or rel] = m.group(1)

    grab("skill.yaml", r"^version:\s*(\S+)")
    grab("SKILL.md", r'version:\s*"([^"]+)"')
    grab("pyproject.toml", r'^version\s*=\s*"([^"]+)"')
    grab("README.md", r"^Version\s+(\S+)")
    grab(os.path.join("scripts", "nar.py"), r'VERSION\s*=\s*"([^"]+)"')
    grab(os.path.join("scripts", "narlib", "__init__.py"),
         r'__version__\s*=\s*"([^"]+)"')
    grab(os.path.join("scripts", "nar-analyze.py"),
         r'NAR_VERSION\s*=\s*"([^"]+)"')
    plugin = json.loads(_read(root, os.path.join(
        ".claude-plugin", "plugin.json")))
    found[".claude-plugin/plugin.json"] = plugin["version"]
    reg = json.loads(_read(root, os.path.join("scripts", "registry.json")))
    found["scripts/registry.json"] = reg["registry_version"]
    for mod in ("nar-assets", "nar-dex", "nar-engines", "nar-native",
                "nar-network", "nar-runtime", "nar-security", "nar-unity",
                "nar-unreal"):
        rel = os.path.join("scripts", mod + ".py")
        versions = re.findall(r'"version":\s*"([^"]+)"', _read(root, rel))
        if versions:
            found[rel] = versions[0]
            assert len(set(versions)) == 1, (rel, versions)
    return found


VERSION_FILES = [
    "skill.yaml", "SKILL.md", "pyproject.toml", "README.md",
    os.path.join(".claude-plugin", "plugin.json"),
    os.path.join("scripts", "nar.py"),
    os.path.join("scripts", "narlib", "__init__.py"),
    os.path.join("scripts", "nar-analyze.py"),
    os.path.join("scripts", "registry.json"),
    os.path.join("scripts", "nar-assets.py"),
    os.path.join("scripts", "nar-dex.py"),
    os.path.join("scripts", "nar-engines.py"),
    os.path.join("scripts", "nar-native.py"),
    os.path.join("scripts", "nar-network.py"),
    os.path.join("scripts", "nar-runtime.py"),
    os.path.join("scripts", "nar-security.py"),
    os.path.join("scripts", "nar-unity.py"),
    os.path.join("scripts", "nar-unreal.py"),
]


class ReadmeStructureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.block = _structure_block(_read(ROOT, "README.md"))

    def _assert_all_named(self, rel_dir, suffixes):
        base = os.path.join(ROOT, rel_dir)
        for name in sorted(os.listdir(base)):
            if name == "__pycache__":
                continue
            if os.path.isfile(os.path.join(base, name)) and \
                    name.endswith(suffixes):
                self.assertIn(name, self.block,
                              "%s/%s missing from README structure block"
                              % (rel_dir, name))

    def test_references_all_named_and_counted(self):
        self._assert_all_named("references", (".md",))
        actual = len([n for n in os.listdir(os.path.join(ROOT, "references"))
                      if n.endswith(".md")])
        m = re.search(r"\((\d+) guides\)", self.block)
        self.assertIsNotNone(m, "structure block must state the guide count")
        self.assertEqual(int(m.group(1)), actual)

    def test_scripts_all_named(self):
        self._assert_all_named("scripts", (".py", ".sh", ".json"))

    def test_narlib_all_named(self):
        self._assert_all_named(os.path.join("scripts", "narlib"), (".py",))

    def test_frida_all_named(self):
        self._assert_all_named(os.path.join("scripts", "frida"), (".js",))

    def test_schemas_all_named(self):
        self._assert_all_named("schemas", (".json",))

    def test_tests_layout_named(self):
        for token in ("run_e2e.sh", "unit/", "benchmarks/",
                      "run_benchmarks.py"):
            self.assertIn(token, self.block)


class SkillRoutingTest(unittest.TestCase):
    def test_skill_link_targets_exist(self):
        text = _read(ROOT, "SKILL.md")
        targets = set(re.findall(r"\(((?:references|scripts)/[^)\s]+)\)",
                                 text))
        self.assertTrue(targets, "SKILL.md must route to files")
        for rel in sorted(targets):
            self.assertTrue(os.path.isfile(os.path.join(ROOT, rel)),
                            "SKILL.md routes to missing file: " + rel)


class VersionConsistencyTest(unittest.TestCase):
    def test_all_version_bearing_files_agree(self):
        found = collect_versions(ROOT)
        self.assertGreaterEqual(len(found), 15,
                                "expected the full version-bearing set")
        distinct = set(found.values())
        self.assertEqual(len(distinct), 1,
                         "version divergence: %r" % (found,))

    def test_planted_mismatch_is_detected(self):
        tmp = tempfile.mkdtemp(prefix="nar-version-plant-")
        try:
            for rel in VERSION_FILES:
                dst = os.path.join(tmp, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copyfile(os.path.join(ROOT, rel), dst)
            path = os.path.join(tmp, "skill.yaml")
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            text = re.sub(r"^version:.*$", "version: 0.0.0-planted",
                          text, count=1, flags=re.M)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            found = collect_versions(tmp)
            self.assertGreater(len(set(found.values())), 1,
                               "planted mismatch must be detected")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_headline_carries_no_version(self):
        # Phase 1 resolution: the brand headline no longer embeds
        # a version number, so it cannot diverge from the release
        # version again (the version lives in the guarded files).
        readme = _read(ROOT, "README.md")
        self.assertIn("# NAR — NIROUS ANDROID INTELLIGENCE", readme)
        pyproject = _read(ROOT, "pyproject.toml")
        self.assertIn("NAR — NIROUS ANDROID INTELLIGENCE", pyproject)
        self.assertNotIn("NAR 2.0 —", readme)
        self.assertNotIn("NAR 2.0 —", pyproject)


@unittest.skipIf(yaml is None,
                 "PyYAML is not installed, so real YAML parsing "
                 "cannot run; install the pyproject 'test'/'dev' "
                 "extras (pyyaml) to enable this check")
class YamlValidityTest(unittest.TestCase):
    """Parser-based augmentation of the regex version grabs
    (2.5.2 W1): skill.yaml and the SKILL.md frontmatter must
    parse with a real YAML parser, and the parsed versions
    must agree with the regex-collected ones. The full parser
    suite lives in tests/unit/test_yaml_validation.py."""

    def test_skill_yaml_parses_and_version_agrees(self):
        data = yaml.safe_load(_read(ROOT, "skill.yaml"))
        self.assertIsInstance(data, dict)
        self.assertIsInstance(data["name"], str)
        self.assertIsInstance(data["description"], str)
        self.assertTrue(data["description"].strip())
        self.assertIsInstance(data["include_in_prompt"], bool)
        found = collect_versions(ROOT)
        self.assertEqual(str(data["version"]), found["skill.yaml"])

    def test_skill_md_frontmatter_parses_and_version_agrees(self):
        text = _read(ROOT, "SKILL.md")
        self.assertTrue(text.startswith("---\n"))
        front = text.split("---\n", 2)[1]
        data = yaml.safe_load(front)
        self.assertIsInstance(data, dict)
        self.assertEqual(data["name"], "nar")
        self.assertIsInstance(data["description"], str)
        self.assertTrue(data["description"].strip())
        found = collect_versions(ROOT)
        self.assertEqual(data["metadata"]["version"], found["SKILL.md"])


if __name__ == "__main__":
    unittest.main()
