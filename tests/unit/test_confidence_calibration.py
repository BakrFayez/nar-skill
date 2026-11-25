"""2.6.2 WS-E3 — confidence calibration regression tests.

The audit found one overstated label: nar-network's
endpoint classification "confirmed", whose documented
meaning was "referenced from DEX code" while its evidence
rule was only that the URL string appears in DEX string
data (nar-strings scans entry bytes). A string-table
entry is not a code reference — narlib.correlations
treats the same evidence as STRONGLY_INDICATED for
exactly that reason. The label is now "dex-string".

These tests pin the calibrated behavior: DEX-sourced
endpoints classify as "dex-string", the word "confirmed"
is never emitted as an endpoint classification, and the
endpoints schema enum matches.
"""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, str(SCRIPTS / filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


net = _load("nar_network_calibration", "nar-network.py")


def test_dex_sourced_endpoint_is_dex_string_not_confirmed():
    classification, host, _kind = net.classify(
        "https://api.example.com/v1/items", ["classes.dex"])
    assert classification == "dex-string"
    assert host == "api.example.com"


def test_no_synthetic_endpoint_classifies_confirmed():
    import sys
    sys.path.insert(0, str(ROOT / "tests" / "accuracy"))
    import corpus
    for sample in corpus.synthetic_endpoint_samples():
        got, _host, _kind = net.classify(
            sample["url"], sample["sources"])
        assert got != "confirmed"
        assert got == sample["expected"]


def test_endpoints_schema_enum_is_calibrated():
    schema = json.loads(
        (ROOT / "schemas" / "endpoints.schema.json").read_text())
    enum = schema["properties"]["endpoints"]["items"][
        "properties"]["classification"]["enum"]
    assert "dex-string" in enum
    assert "confirmed" not in enum
