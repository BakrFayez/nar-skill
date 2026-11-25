"""Unit tests: brief-named companion projections
(Evolution Phase 2) + AAR/JAR structural summaries +
compile_sdk badging parse.

Projections are pure functions over stage-shaped data; each
result is validated against the shipped JSON schema.
"""
import importlib.util
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
from narlib import companions, evidence, formats  # noqa: E402


def _schema(name):
    with open(os.path.join(ROOT, "schemas", name),
              encoding="utf-8") as fh:
        return json.load(fh)


def _prop(value, provenance="test"):
    return {"value": value, "provenance": provenance,
            "confidence": "high", "fact_class": "observed"}


FP_DOC = {
    "source_sha256": "a" * 64,
    "properties": {
        "package": _prop("com.example.demo"),
        "version_name": _prop("1.0"),
        "version_code": _prop("1"),
        "min_sdk": _prop("24"),
        "target_sdk": _prop("34"),
        "compile_sdk": _prop("34"),
        "engine_hints": _prop(["Unity"]),  # not an application key
    },
    "notes": [],
}

NATIVE_DOC = {
    "libraries": [
        {"name": "lib/arm64-v8a/libdemo.so",
         "display_name": "arm64-v8a/libdemo.so",
         "elf_class": "ELF64", "arch": "aarch64",
         "soname": "libdemo.so", "size_bytes": 100,
         "needed": ["liblog.so"], "build_id": "ab12",
         "jni_exports": ["JNI_OnLoad"]},
        {"name": "lib/arm64-v8a/libbad.so", "error": "truncated"},
    ],
    "jni_map": {"arm64-v8a/libdemo.so": ["JNI_OnLoad"]},
    "dependency_graph": {"libdemo.so": ["liblog.so"]},
}

ENGINES_DOC = {
    "verdicts": [{"engine": "unity", "detected": True,
                  "confidence": "high", "score": 12,
                  "version": "2022.3"}],
    "ambiguities": [],
}


class CompanionsTest(unittest.TestCase):
    def test_application_projection_validates(self):
        doc = companions.project_application(FP_DOC, "2.4.0")
        self.assertEqual(
            evidence.validate(doc, _schema("application.schema.json")),
            [])
        self.assertEqual(
            doc["properties"]["compile_sdk"]["value"], "34")
        # Non-application fingerprint properties stay out.
        self.assertNotIn("engine_hints", doc["properties"])

    def test_application_unavailable_is_explicit(self):
        doc = companions.project_application(None, "2.4.0")
        self.assertIn("unavailable", doc)
        self.assertEqual(
            evidence.validate(doc, _schema("application.schema.json")),
            [])

    def test_manifest_projection_validates(self):
        summary = {"package": "com.example.demo",
                   "permission_count": 2,
                   "permissions_by_group": {"normal": 2},
                   "dangerous_permissions": [],
                   "component_counts": {"activity": 1},
                   "exported_count": 1, "debuggable": False,
                   "allow_backup": True, "target_sdk": "34",
                   "is_split": False}
        doc = companions.project_manifest(summary, {}, "2.4.0")
        self.assertEqual(
            evidence.validate(doc, _schema("manifest.schema.json")),
            [])
        self.assertEqual(doc["permission_count"], 2)

    def test_manifest_degraded_stage_is_explicit(self):
        doc = companions.project_manifest(
            {"error": "nar-perms failed"}, {}, "2.4.0")
        self.assertIn("unavailable", doc)
        self.assertEqual(
            evidence.validate(doc, _schema("manifest.schema.json")),
            [])

    def test_native_inventory_projection_validates(self):
        doc = companions.project_native_inventory(NATIVE_DOC, "2.4.0")
        self.assertEqual(
            evidence.validate(
                doc, _schema("native-inventory.schema.json")), [])
        self.assertEqual(doc["library_count"], 2)
        self.assertEqual(doc["libraries"][1]["error"], "truncated")
        self.assertEqual(doc["jni_libraries"],
                         ["arm64-v8a/libdemo.so"])

    def test_frameworks_projection_validates(self):
        doc = companions.project_frameworks(ENGINES_DOC, FP_DOC,
                                             "2.4.0")
        self.assertEqual(
            evidence.validate(doc, _schema("frameworks.schema.json")),
            [])
        self.assertEqual(doc["verdicts"][0]["engine"], "unity")
        self.assertEqual(doc["markers"]["engine_hints"], ["Unity"])


def _zip_bytes(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


class ArchiveStructureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nar-archive-")

    def _write(self, name, data):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def test_aar_structure_summary(self):
        classes_jar = _zip_bytes({
            "com/example/A.class": b"\xca\xfe\xba\xbe",
            "com/example/B.class": b"\xca\xfe\xba\xbe"})
        aar = _zip_bytes({
            "AndroidManifest.xml": b"<manifest/>",
            "classes.jar": classes_jar,
            "R.txt": "int string app_name 0x7f000000",
            "res/values/strings.xml": "<resources/>",
            "jni/arm64-v8a/libx.so": b"\x7fELF",
            "META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n"})
        path = self._write("lib.aar", aar)
        self.assertEqual(formats.identify(path)["format"], "aar")
        summary = formats.archive_structure_summary(path)
        self.assertTrue(summary["has_android_manifest"])
        self.assertTrue(summary["has_classes_jar"])
        self.assertEqual(summary["classes_jar_class_count"], 2)
        self.assertTrue(summary["has_r_txt"])
        self.assertEqual(summary["res_entries"], 1)
        self.assertEqual(summary["jni_libraries"],
                         ["jni/arm64-v8a/libx.so"])

    def test_jar_structure_summary(self):
        jar = _zip_bytes({
            "META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n",
            "com/example/A.class": b"\xca\xfe\xba\xbe",
            "com/example/B.class": b"\xca\xfe\xba\xbe"})
        path = self._write("plain.jar", jar)
        self.assertEqual(formats.identify(path)["format"], "jar")
        summary = formats.archive_structure_summary(path)
        self.assertEqual(summary["class_entries"], 2)
        self.assertTrue(summary["has_manifest_mf"])

    def test_jar_missing_manifest_reported_not_inferred(self):
        # A class-only archive identifies as a plain zip (the
        # shipped identification rule); summarized explicitly
        # as a jar, the missing MANIFEST.MF is a reported fact.
        jar = _zip_bytes({
            "com/example/A.class": b"\xca\xfe\xba\xbe",
            "com/example/B.class": b"\xca\xfe\xba\xbe",
            "com/example/C.class": b"\xca\xfe\xba\xbe"})
        path = self._write("nomanifest.jar", jar)
        self.assertEqual(formats.identify(path)["format"], "zip")
        summary = formats.archive_structure_summary(path, "jar")
        self.assertEqual(summary["class_entries"], 3)
        self.assertFalse(summary["has_manifest_mf"])

    def test_non_archive_formats_have_no_summary(self):
        path = self._write("x.dex", b"dex\n038\x00" + b"\x00" * 120)
        self.assertIsNone(formats.archive_structure_summary(path))


class CompileSdkBadgingTest(unittest.TestCase):
    """aapt2_badging parses compileSdkVersion off the package
    line (planted stub aapt2 on PATH)."""

    BADGING = (
        "package: name='com.example.demo' versionCode='7' "
        "versionName='1.2' platformBuildVersionName='14' "
        "platformBuildVersionCode='34' compileSdkVersion='34' "
        "compileSdkVersionCodename='14'\n"
        "sdkVersion:'24'\n"
        "targetSdkVersion:'34'\n"
        "application-label:'Demo'\n")

    def test_compile_sdk_parsed(self):
        tmp = tempfile.mkdtemp(prefix="nar-aapt2-stub-")
        stub = os.path.join(tmp, "aapt2")
        with open(stub, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\ncat <<'EOF'\n" + self.BADGING
                     + "EOF\n")
        os.chmod(stub, os.stat(stub).st_mode | stat.S_IEXEC)
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = tmp + os.pathsep + old_path
        try:
            spec = importlib.util.spec_from_file_location(
                "nar_triage", os.path.join(ROOT, "scripts",
                                           "nar-triage.py"))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            info, status = mod.aapt2_badging("whatever.apk")
        finally:
            os.environ["PATH"] = old_path
        self.assertEqual(status, "ok")
        self.assertEqual(info.get("compile_sdk"), "34")
        self.assertEqual(info.get("package"), "com.example.demo")

    def _load_triage(self):
        spec = importlib.util.spec_from_file_location(
            "nar_triage", os.path.join(ROOT, "scripts",
                                       "nar-triage.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def _plant_stub(self):
        tmp = tempfile.mkdtemp(prefix="nar-aapt2-win-")
        stub = os.path.join(tmp, "aapt2")
        with open(stub, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\ncat <<'EOF'\n" + self.BADGING
                     + "EOF\n")
        os.chmod(stub, os.stat(stub).st_mode | stat.S_IEXEC)
        return tmp, stub

    def test_find_aapt2_windows_extensionless_on_path(self):
        # Windows: shutil.which only tries the PATHEXT
        # extensions, so an extensionless aapt2 planted on
        # PATH is invisible to it; find_aapt2's own PATH
        # scan must still locate it. Simulated platform —
        # no Windows host required.
        tmp, stub = self._plant_stub()
        mod = self._load_triage()
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = tmp
        try:
            with mock.patch.object(sys, "platform", "win32"), \
                    mock.patch.object(
                        shutil, "which",
                        lambda name, path=None: None):
                self.assertEqual(mod.find_aapt2(), stub)
        finally:
            os.environ["PATH"] = old_path

    def test_aapt2_argv_windows_wrappers(self):
        # Windows cannot CreateProcess a wrapper: .bat/.cmd
        # go through cmd, a shebang script through sh, and a
        # native .exe runs directly. POSIX argv is the bare
        # candidate, unchanged.
        tmp, stub = self._plant_stub()
        mod = self._load_triage()
        self.assertEqual(
            mod._aapt2_argv(stub, "dump", "badging", "x.apk"),
            [stub, "dump", "badging", "x.apk"])

        def fake_which(name, path=None):
            return "/fake/sh" if name == "sh" else None

        with mock.patch.object(sys, "platform", "win32"), \
                mock.patch.object(shutil, "which", fake_which):
            self.assertEqual(
                mod._aapt2_argv("C:\\sdk\\aapt2.exe", "dump"),
                ["C:\\sdk\\aapt2.exe", "dump"])
            self.assertEqual(
                mod._aapt2_argv("C:\\sdk\\aapt2.bat", "dump"),
                ["cmd", "/c", "C:\\sdk\\aapt2.bat", "dump"])
            self.assertEqual(
                mod._aapt2_argv(stub, "dump"),
                ["/fake/sh", stub, "dump"])

    def test_compile_sdk_parsed_windows_simulated(self):
        # The hosted-Windows failure mode, simulated end to
        # end: which() cannot see the extensionless stub
        # (PATHEXT) and the platform cannot execute a
        # shebang script directly, so find_aapt2 must locate
        # the stub by scanning PATH and aapt2_badging must
        # run it through sh. The parsed values must then be
        # identical to the POSIX run above.
        tmp, stub = self._plant_stub()
        mod = self._load_triage()
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = tmp + os.pathsep + old_path
        # Resolved BEFORE the platform patch: under a
        # simulated win32, shutil.which itself takes its
        # Windows branch and cannot be delegated to.
        real_sh = shutil.which("sh")

        def fake_which(name, path=None):
            if name == "aapt2":
                return None  # the PATHEXT miss, as on Windows
            if name == "sh":
                return real_sh
            return None

        try:
            with mock.patch.object(sys, "platform", "win32"), \
                    mock.patch.object(shutil, "which",
                                      fake_which):
                info, status = mod.aapt2_badging("whatever.apk")
        finally:
            os.environ["PATH"] = old_path
        self.assertEqual(status, "ok")
        self.assertEqual(info.get("compile_sdk"), "34")
        self.assertEqual(info.get("package"), "com.example.demo")


if __name__ == "__main__":
    unittest.main()
