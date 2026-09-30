"""Live Binary Ninja validation harness for dotninja views."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any
from binaryninja import AnalysisCompletionEvent, BackgroundTaskThread, PluginCommand
from binaryninja.log import log_error, log_info

MANIFEST_PATH = Path(__file__).with_name("fixtures") / "manifest.json"
_completion_events: list[Any] = []

@dataclass
class ValidationCheck:
    name: str
    status: str
    expected: Any = None
    observed: Any = None
    address: int | None = None
    details: str = ""

@dataclass
class ValidationReport:
    fixture_id: str | None = None
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: str | None = None
    checks: list[ValidationCheck] = field(default_factory=list)
    observed_addresses: dict[str, int] = field(default_factory=dict)

    def add(self, name, passed, expected=None, observed=None, address=None, details=""):
        self.checks.append(ValidationCheck(name, "pass" if passed else "fail", expected, observed, address, details))

    @property
    def summary(self):
        return {"passed": sum(x.status == "pass" for x in self.checks), "failed": sum(x.status == "fail" for x in self.checks), "total": len(self.checks)}

    def to_dict(self):
        result = asdict(self)
        result["summary"] = self.summary
        return result

    def to_markdown(self):
        summary = self.summary
        lines = ["# dotninja Validation", "", f"Fixture: `{self.fixture_id or 'generic'}`", f"Result: **{summary['passed']} passed, {summary['failed']} failed**", "", "| Check | Status | Expected | Observed |", "|---|---:|---|---|"]
        for check in self.checks:
            lines.append(f"| {check.name} | {check.status.upper()} | `{check.expected}` | `{check.observed}` |")
            if check.details:
                lines.append(f"\n{check.details}\n")
        return "\n".join(lines)

def load_fixture_manifest():
    if not MANIFEST_PATH.exists():
        return {"schema": 1, "fixtures": {}}
    data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if data.get("schema") != 1 or not isinstance(data.get("fixtures"), dict):
        raise ValueError("invalid fixture manifest")
    return data

def fixture_for_view(bv):
    digest = bv.session_data.get("dotninja.original_sha256")
    for fixture_id, oracle in load_fixture_manifest()["fixtures"].items():
        if oracle.get("sha256") == digest:
            return fixture_id, oracle
    return None, None

def validate_view(bv, fixture_oracle=None) -> ValidationReport:
    from .arch import decode_instruction
    fixture_id = fixture_oracle.get("id") if fixture_oracle else None
    report = ValidationReport(fixture_id=fixture_id)
    report.add("dotninja view", getattr(bv, "view_type", "") == "DotNet", "DotNet", getattr(bv, "view_type", ""))
    expected_arch = "dotnet64" if int(bv.address_size) == 8 else "dotnet32"
    report.add("architecture width", getattr(bv.arch, "name", "") == expected_arch, expected_arch, getattr(bv.arch, "name", ""))
    bodies = bv.session_data.get("method_bodies", {})
    report.add("parsed method bodies", bool(bodies), ">=1", len(bodies))
    targets = bv.session_data.get("token_targets", {})
    callable_addresses = {int(f.start) for f in bv.functions}
    bad_fields = [t.token for t in targets.values() if getattr(t, "kind", None) == "field" and getattr(t, "address", None) in callable_addresses]
    report.add("field references are data", not bad_fields, [], [hex(x) for x in bad_fields])
    for start, body in bodies.items():
        cursor, end, issue = int(start), int(start) + int(body.code_size), None
        while cursor < end:
            data = bv.read(cursor, bv.arch.max_instr_length)
            opcode, _, length = decode_instruction(data, cursor)
            if not opcode or length <= 0 or cursor + length > end:
                issue = f"invalid instruction at {cursor:#x}"
                break
            text, text_len = bv.arch.get_instruction_text(data, cursor)
            info = bv.arch.get_instruction_info(data, cursor)
            if text_len != length or info.length != length or not text:
                issue = f"inconsistent decode at {cursor:#x}"
                break
            cursor += length
        report.add(f"method {start:#x} instruction bounds", issue is None, body.code_size, cursor - int(start), start, issue or "")
        report.observed_addresses[f"method_{start:x}"] = int(start)
    if fixture_oracle:
        expected_methods = fixture_oracle.get("methods", {})
        for token_text, expected in expected_methods.items():
            token = int(token_text, 0)
            target = targets.get(token)
            observed = getattr(target, "address", None)
            report.add(f"method token {token_text}", observed == expected.get("address"), expected.get("address"), observed, observed)
        for section_name in fixture_oracle.get("sections", []):
            section = bv.get_section_by_name(section_name)
            report.add(f"section {section_name}", section is not None, True, section is not None)
    report.finished_at = datetime.now(timezone.utc).isoformat()
    bv.session_data["dotninja.validation"] = report.to_dict()
    return report

class _ValidationTask(BackgroundTaskThread):
    def __init__(self, bv, oracle=None, show=True):
        super().__init__("dotninja validation", False)
        self.bv, self.oracle, self.show = bv, oracle, show
    def run(self):
        try:
            self.bv.update_analysis_and_wait()
            if self.oracle:
                from .analyzer import DotNetAnalyzer
                for function in list(self.bv.functions):
                    DotNetAnalyzer.decrypt_strings(self.bv, function)
                    DotNetAnalyzer.remove_opaque_predicates(self.bv, function)
                self.bv.update_analysis_and_wait()
            report = validate_view(self.bv, self.oracle)
            if self.show:
                self.bv.show_markdown_report("dotninja Validation", report.to_markdown())
        except Exception as exc:
            log_error(f"[dotninja] Validation failed: {exc}")

def run_validation_command(bv):
    _, oracle = fixture_for_view(bv)
    _ValidationTask(bv, oracle, True).start()

def validation_is_valid(bv):
    return getattr(bv, "view_type", "") == "DotNet"

def arm_automatic_validation(bv):
    fixture_id, oracle = fixture_for_view(bv)
    if not oracle or bv.session_data.get("dotninja.validation.auto_started"):
        return
    oracle = dict(oracle)
    oracle["id"] = fixture_id
    bv.session_data["dotninja.validation.auto_started"] = True
    def completed(*_args):
        _ValidationTask(bv, oracle, True).start()
    event = AnalysisCompletionEvent(bv, completed)
    _completion_events.append(event)

def register_validation_plugin():
    PluginCommand.register("dotninja \\ Run Validation Suite", "Validate the live CLR view and show a structured report", run_validation_command, validation_is_valid)
