"""Unit tests: registry integrity + probing."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..",
                                "scripts"))
from narlib import registry  # noqa: E402


class RegistryTest(unittest.TestCase):
    def test_registry_loads_and_is_complete(self):
        reg = registry.load_registry()
        names = [t["name"] for t in reg["tools"]]
        self.assertEqual(len(names), len(set(names)),
                         "tool names must be unique")
        for entry in reg["tools"]:
            for key in ("name", "kind", "required", "platforms",
                        "limitations", "validation"):
                self.assertIn(key, entry, entry["name"])
            self.assertIn(entry["kind"],
                          ("cli", "jar", "dotnet", "python-module",
                           "unavailable"))

    def test_unavailable_tools_probe_unavailable(self):
        reg = registry.load_registry()
        for entry in reg["tools"]:
            if entry["kind"] == "unavailable":
                result = registry.probe(entry)
                self.assertFalse(result["available"], entry["name"])

    def test_python3_probes_available(self):
        reg = registry.load_registry()
        entry = next(t for t in reg["tools"]
                     if t["name"] == "python3")
        result = registry.probe(entry)
        self.assertTrue(result["available"])
        self.assertIsNotNone(result["path"])


if __name__ == "__main__":
    unittest.main()
