"""Unit tests: nar-doctor.sh interpreter resolution guard (Part 10).

Defect: scripts/nar-doctor.sh resolved its Python interpreter
with a single python3-only lookup. On a python-only system
(stock Windows, where the interpreter is `python` or the
`py -3` launcher) the lookup found nothing, so the core
nar-scripts and protection-signatures self-checks — both
gated on the resolved interpreter — reported missing and
core_ok was false even with a working Python 3.10+ present.

These tests pin the fix in the script text:

- the resolution chain exists, in order: $NAR_PYTHON,
  python3, python, py -3;
- no line assigns the interpreter variable directly from
  a bare `command -v python3` lookup (the old form);
- candidates are probed for Python >= 3.10 before use;
- every Python self-check routes through the resolved
  interpreter (py_exec), never a bare python3 invocation;
- the --json output carries the python_resolved field.
"""
import os
import re

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DOCTOR = os.path.join(ROOT, "scripts", "nar-doctor.sh")

# The exact pre-Part-10 resolution line. Reintroducing it
# (or any equivalent single-name assignment) must fail.
OLD_FORM = 'PY_BIN="$(command -v python3 || true)"'
BARE_ASSIGN_RE = re.compile(
    r"""^\s*PY_BIN\s*=\s*"?\$\(\s*command\s+-v\s+python3\b""", re.M)


def _text():
    with open(DOCTOR, encoding="utf-8") as fh:
        return fh.read()


def _code_lines(text):
    """Script lines with full-line comments removed."""
    return [ln for ln in text.splitlines()
            if not ln.lstrip().startswith("#")]


def test_no_bare_python3_only_assignment():
    text = _text()
    assert OLD_FORM not in text
    for line in _code_lines(text):
        assert not BARE_ASSIGN_RE.match(line), line


def test_resolution_chain_exists_in_order():
    text = _text()
    i_env = text.index("NAR_PYTHON")
    i_py3 = text.index('_py_try "python3"')
    i_py = text.index('_py_try "python"')
    i_launcher = text.index('_py_try "py" "-3"')
    assert i_env < i_py3 < i_py < i_launcher


def test_candidates_are_version_probed():
    text = _text()
    # The probe reads the candidate's own version and the
    # acceptance check enforces the 3.10 floor.
    assert "sys.version_info" in text
    assert "_py_version_ok" in text
    assert "_py_probe" in text


def test_self_checks_route_through_resolved_interpreter():
    text = _text()
    code = "\n".join(_code_lines(text))
    # No bare python3 invocation anywhere in code: the
    # version line and every self-check must go through
    # the resolved interpreter.
    assert "$(python3" not in code
    assert '"$PY_BIN" -c' not in code
    assert '"$PY_BIN" -m' not in code
    # The resolved-interpreter runner exists and is used
    # by the nar-scripts, protection-signatures and
    # skill-yaml checks (compile, py_compile fallback,
    # signatures JSON load, yaml import + parse).
    assert "py_exec()" in code
    assert code.count("py_exec ") >= 4


def test_json_reports_python_resolved():
    text = _text()
    assert '"python_resolved"' in text
    assert "PY_RESOLVED" in text


def test_matcher_fires_on_the_old_string():
    # The guard above is only worth anything if its
    # matcher actually fires on the pre-fix form; pin
    # that here against the literal old line so a future
    # refactor of the matcher cannot silently disarm it.
    assert BARE_ASSIGN_RE.match(OLD_FORM)
    sample = "# doctor\n" + OLD_FORM + "\ncheck x\n"
    assert any(BARE_ASSIGN_RE.match(ln)
               for ln in _code_lines(sample))
