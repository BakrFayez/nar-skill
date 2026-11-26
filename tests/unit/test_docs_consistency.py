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
  and a planted mismatch in a temp copy is detected;
- the project credit line appears exactly once in the
  whole tree, in the README Author section (owner-directed
  placement: tool outputs and document headers carry no
  credit stamp);
- every CI job count stated in the current-release records
  equals the expanded total derived from the workflow file
  itself, and the README Documentation section's guide
  count equals the top-level references/ tree (E-04: the
  F-001 / E-01 drift class, guarded after the fact).
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
    os.path.join("scripts", "nar-compare.py"),
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

    def test_docs_all_named(self):
        # The engineering reports moved from the repo root
        # into docs/ (owner-directed layout cleanup); every
        # report the docs/ tree carries must be named in the
        # structure block, like every other directory here.
        self._assert_all_named("docs", (".md",))

    def test_tests_layout_named(self):
        for token in ("run_e2e.sh", "unit/", "benchmarks/",
                      "run_benchmarks.py"):
            self.assertIn(token, self.block)
        # Enumerate the real tests/ tree (E-10): every
        # entry the tree carries must be named in the
        # README structure block, not just four tokens.
        tests_dir = os.path.join(ROOT, "tests")
        for name in sorted(os.listdir(tests_dir)):
            if name == "__pycache__":
                continue
            full = os.path.join(tests_dir, name)
            token = name + "/" if os.path.isdir(full) else name
            self.assertIn(
                token, self.block,
                f"tests/{name} missing from README "
                "structure block")
        bench_dir = os.path.join(tests_dir, "benchmarks")
        for name in sorted(os.listdir(bench_dir)):
            if name == "__pycache__" or \
                    not name.endswith((".py", ".json")):
                continue
            self.assertIn(
                name, self.block,
                f"tests/benchmarks/{name} missing from "
                "README structure block")


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


class CreditLinePlacementTest(unittest.TestCase):
    """The credit line lives in exactly one place: the
    README Author section. Built from parts so this test
    file never contains the phrase itself."""

    PHRASE = "Research by " + "Bakr Fayez"

    def _occurrences(self):
        found = {}
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames
                           if d not in (".git", "__pycache__")]
            for name in filenames:
                path = os.path.join(dirpath, name)
                try:
                    with open(path, encoding="utf-8",
                              errors="ignore") as fh:
                        text = fh.read()
                except OSError:
                    continue
                count = re.sub(r"\s+", " ", text).count(self.PHRASE)
                if count:
                    found[os.path.relpath(path, ROOT)] = count
        return found

    def test_credit_line_exactly_once_in_readme(self):
        self.assertEqual(self._occurrences(), {"README.md": 1})

    def test_credit_line_inside_author_section(self):
        readme = _read(ROOT, "README.md")
        at = readme.index(self.PHRASE)
        self.assertGreater(at, readme.index("## Author"))
        self.assertLess(at, readme.index("## License"))


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


class SupportedGuideTest(unittest.TestCase):
    """Part 9 rule (3.0 knowledge base): a registry entry may
    claim `supported` only if its guide section exists. The
    section mapping follows the Part 9 guide table: engines
    get one file per family under references/engines/, the
    other registries get a headed section in their topical
    guide. Existence of the section is pinned here; that the
    section shows a real command with a real output shape is
    established by the guide-production record (the guides
    were written from captured runs)."""

    GUIDE_FOR_SECTION = {
        "asset_formats": "asset-formats.md",
        "script_formats": "script-formats.md",
        "animation_systems": "animation-systems.md",
        "app_frameworks": "app-patterns.md",
        "protection_kinds": "protection-playbook.md",
    }

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, "scripts", "coverage.json"),
                  encoding="utf-8") as fh:
            cls.coverage = json.load(fh)

    def test_supported_engines_have_a_family_guide(self):
        for entry in self.coverage["engines"]:
            if entry["status"] != "supported":
                continue
            rel = os.path.join("references", "engines",
                               entry["id"] + ".md")
            path = os.path.join(ROOT, rel)
            self.assertTrue(os.path.isfile(path),
                            "supported engine %s has no guide: %s"
                            % (entry["id"], rel))
            self.assertGreater(os.path.getsize(path), 400,
                               "guide for %s is a stub" % entry["id"])

    def test_supported_entries_have_a_guide_section(self):
        for section, guide in self.GUIDE_FOR_SECTION.items():
            text = _read(ROOT, os.path.join("references", guide))
            heading_lines = re.findall(r"^##\s+(.+)$", text, re.M)
            heading_tokens = set()
            for line in heading_lines:
                heading_tokens.update(re.findall(r"[a-z0-9][a-z0-9_-]*",
                                                 line))
            for entry in self.coverage[section]:
                if entry["status"] != "supported":
                    continue
                self.assertIn(
                    entry["id"], heading_tokens,
                    "supported %s entry %s has no section in %s"
                    % (section, entry["id"], guide))


WORKFLOW_REL = os.path.join(".github", "workflows", "ci.yml")

JOB_COUNT_GUARDED_FILES = [
    "CHANGELOG.md",
    os.path.join("docs", "NAR_3.0.0_UPDATE_REPORT.md"),
    WORKFLOW_REL,
]

# Statement shapes pinned by the job-count guard (F-001): the
# current-release records state the expanded hosted count as
# "all N jobs pass / PASS / green". Scoping, deliberately
# narrow: era-correct historical statements never match these
# shapes — the 2.6.2-era counts are written as words ("nine
# jobs", in the CHANGELOG, the final verification report and
# the workflow header) or as "all 9 CI jobs executed" (an
# intervening "CI" and a different verb, CHANGELOG 2.6.2
# section), and files outside the guarded set are not scanned
# at all. Only the three current-record files above can carry
# the current count, so only they are guarded.
JOB_COUNT_PATTERNS = [
    re.compile(r"all (\d+) jobs\b"),
    re.compile(r"(\d+) jobs (?:pass|PASS|green)\b"),
]


def parse_workflow_jobs(text):
    """Stdlib-only structural read of ci.yml (no PyYAML: the
    guard must run wherever the docs suite runs).

    Returns {job_name: [os, ...] or None} for the job
    definitions under the top-level `jobs:` mapping; a job's
    list is its strategy.matrix.os entries (inline flow list
    or block list), None when the job has no matrix."""
    jobs = {}
    in_jobs = False
    current = None
    os_indent = None
    for line in text.splitlines():
        if not in_jobs:
            if re.match(r"^jobs:\s*$", line):
                in_jobs = True
            continue
        if line and not line.startswith((" ", "#")):
            break  # a later top-level key ends the jobs mapping
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            current = m.group(1)
            jobs[current] = None
            os_indent = None
            continue
        if current is None:
            continue
        m = re.match(r"^(\s+)os:\s*\[(.*)\]\s*$", line)
        if m:
            jobs[current] = [item.strip() for item
                             in m.group(2).split(",") if item.strip()]
            os_indent = None
            continue
        m = re.match(r"^(\s+)os:\s*$", line)
        if m:
            jobs[current] = []
            os_indent = len(m.group(1))
            continue
        if os_indent is not None:
            m = re.match(r"^(\s+)-\s*(\S+)\s*$", line)
            if m and len(m.group(1)) > os_indent:
                jobs[current].append(m.group(2))
            else:
                os_indent = None
    return jobs


def expanded_job_total(root):
    """(jobs, expanded total): each matrix job expands to one
    run per OS in its list; a job without a matrix runs once."""
    jobs = parse_workflow_jobs(_read(root, WORKFLOW_REL))
    total = sum(len(os_list) if os_list else 1
                for os_list in jobs.values())
    return jobs, total


def collect_job_count_statements(root):
    """[(file, stated N)] for every pinned statement shape in
    the guarded current-record files."""
    found = []
    for rel in JOB_COUNT_GUARDED_FILES:
        text = _read(root, rel)
        for pattern in JOB_COUNT_PATTERNS:
            for m in pattern.finditer(text):
                found.append((rel, int(m.group(1))))
    return found


def stated_documentation_guide_count(root):
    """The guide count stated by the README Documentation
    section's sentence (E-01), or None if the sentence's
    phrasing has changed."""
    m = re.search(r"The guides in `references/` \((\d+) guides,"
                  r" one per topic\)", _read(root, "README.md"))
    return int(m.group(1)) if m else None


def actual_reference_guide_count(root):
    return len([n for n in os.listdir(os.path.join(root, "references"))
                if n.endswith(".md")])


class CiJobCountGuardTest(unittest.TestCase):
    """E-04 guard for F-001 and E-01: stated numbers in the
    current-release records are pinned against the tree
    itself — the CI job count against the workflow file's
    structure, the Documentation-section guide count against
    the references/ tree. The documents are never checked
    against a hardcoded expectation; the only hardcoded
    figure is a labelled parser sanity assert."""

    def test_workflow_structure_derives_expanded_total(self):
        jobs, total = expanded_job_total(ROOT)
        # Parser sanity (labelled): today's workflow defines
        # ten jobs. This asserts the PARSER read the file; the
        # document checks below use the derived total, so a
        # future workflow change moves the expectation with it.
        self.assertEqual(len(jobs), 10,
                         "workflow parse sanity: %r" % (jobs,))
        matrix = {name: os_list for name, os_list in jobs.items()
                  if os_list}
        self.assertEqual(len(matrix), 4,
                         "expected the four cross-platform matrix "
                         "jobs: %r" % (jobs,))
        self.assertGreater(total, len(jobs),
                           "matrix expansion must add runs")

    def test_stated_job_counts_match_derived_total(self):
        _, total = expanded_job_total(ROOT)
        statements = collect_job_count_statements(ROOT)
        # Non-vacuous: every guarded file carries at least one
        # pinned statement, so the guard cannot pass by
        # finding nothing.
        self.assertEqual({rel for rel, _ in statements},
                         set(JOB_COUNT_GUARDED_FILES))
        for rel, stated in statements:
            self.assertEqual(
                stated, total,
                "%s states %d jobs; the workflow expands to %d"
                % (rel, stated, total))

    def test_readme_documentation_guide_count_matches_tree(self):
        stated = stated_documentation_guide_count(ROOT)
        self.assertIsNotNone(
            stated, "README Documentation-section guide sentence "
                    "not found; its phrasing changed, so re-pin "
                    "the E-01 guard deliberately")
        self.assertEqual(stated, actual_reference_guide_count(ROOT))

    def test_planted_mismatch_is_detected(self):
        tmp = tempfile.mkdtemp(prefix="nar-jobcount-plant-")
        try:
            for rel in JOB_COUNT_GUARDED_FILES + ["README.md"]:
                dst = os.path.join(tmp, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copyfile(os.path.join(ROOT, rel), dst)
            refs = os.path.join(tmp, "references")
            os.makedirs(refs)
            for name in os.listdir(os.path.join(ROOT, "references")):
                if name.endswith(".md"):
                    open(os.path.join(refs, name), "w").close()
            # Plant the F-001 error back into the CHANGELOG.
            # The wrong statement is built from parts, like the
            # credit phrase above, so this file never contains
            # the literal wrong count itself.
            wrong = "all " + "17" + " jobs pass"
            text = _read(tmp, "CHANGELOG.md")
            planted = re.sub(r"all \d+ jobs pass",
                             wrong, text, count=1)
            self.assertNotEqual(planted, text,
                                "plant must change the statement")
            with open(os.path.join(tmp, "CHANGELOG.md"), "w",
                      encoding="utf-8") as fh:
                fh.write(planted)
            _, total = expanded_job_total(tmp)
            mismatches = [(rel, n) for rel, n
                          in collect_job_count_statements(tmp)
                          if n != total]
            self.assertTrue(mismatches,
                            "planted 17-job statement must be "
                            "detected against the derived total")
            # Plant the E-01 error: 26 back into the README.
            text = _read(tmp, "README.md")
            planted = re.sub(r"\(\d+ guides, one per topic\)",
                             "(26 guides, one per topic)",
                             text, count=1)
            self.assertNotEqual(planted, text,
                                "plant must change the sentence")
            with open(os.path.join(tmp, "README.md"), "w",
                      encoding="utf-8") as fh:
                fh.write(planted)
            self.assertNotEqual(
                stated_documentation_guide_count(tmp),
                actual_reference_guide_count(tmp),
                "planted 26-guide statement must be detected "
                "against the references/ tree")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
