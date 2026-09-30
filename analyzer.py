"""SSA-backed, bounded managed-code deobfuscation commands."""
from __future__ import annotations
import operator
import time
from binaryninja import HighlightStandardColor, MediumLevelILOperation, PluginCommand
from binaryninja.log import log_info, log_warn
from .analysis_core import EmulationError, emulate_pure_cil

def _op_name(expr) -> str:
    return str(getattr(getattr(expr, "operation", None), "name", getattr(expr, "operation", "")))

def _ssa_constant(expr, ssa, depth=0, deadline=None):
    if expr is None or depth > 32 or (deadline is not None and time.monotonic() > deadline):
        return None
    name = _op_name(expr)
    if name in {"MLIL_CONST", "MLIL_CONST_PTR", "MLIL_FLOAT_CONST"}:
        return getattr(expr, "constant", None)
    if name in {"MLIL_VAR_SSA", "MLIL_VAR_PHI"}:
        definition = ssa.get_ssa_var_definition(expr.var)
        return _ssa_constant(getattr(definition, "src", None), ssa, depth + 1, deadline)
    if name.startswith("MLIL_ZX") or name.startswith("MLIL_SX") or name.startswith("MLIL_LOW_PART"):
        return _ssa_constant(getattr(expr, "src", None), ssa, depth + 1, deadline)
    unary = {"MLIL_NEG": operator.neg, "MLIL_NOT": operator.invert, "MLIL_BOOL_TO_INT": int}
    if name in unary:
        value = _ssa_constant(getattr(expr, "src", None), ssa, depth + 1, deadline)
        return unary[name](value) if value is not None else None
    binary = {
        "MLIL_ADD": operator.add, "MLIL_SUB": operator.sub, "MLIL_MUL": operator.mul,
        "MLIL_AND": operator.and_, "MLIL_OR": operator.or_, "MLIL_XOR": operator.xor,
        "MLIL_LSL": operator.lshift, "MLIL_LSR": operator.rshift,
        "MLIL_CMP_E": operator.eq, "MLIL_CMP_NE": operator.ne,
        "MLIL_CMP_SLT": operator.lt, "MLIL_CMP_ULT": operator.lt,
        "MLIL_CMP_SLE": operator.le, "MLIL_CMP_ULE": operator.le,
        "MLIL_CMP_SGT": operator.gt, "MLIL_CMP_UGT": operator.gt,
        "MLIL_CMP_SGE": operator.ge, "MLIL_CMP_UGE": operator.ge,
    }
    if name in binary:
        left = _ssa_constant(getattr(expr, "left", None), ssa, depth + 1, deadline)
        right = _ssa_constant(getattr(expr, "right", None), ssa, depth + 1, deadline)
        if left is None or right is None:
            return None
        try:
            return binary[name](left, right)
        except (ArithmeticError, TypeError, ValueError):
            return None
    return None

class DotNetAnalyzer:
    @staticmethod
    def highlight_reflection(bv):
        found = 0
        for func in bv.functions:
            for block in func.mlil:
                for instr in block:
                    if _op_name(instr) == "MLIL_CALL" and _op_name(instr.dest) == "MLIL_CONST_PTR":
                        sym = bv.get_symbol_at(instr.dest.constant)
                        if sym and any(x in sym.name.lower() for x in ("assembly::load", "methodbase::invoke", "marshal::copy")):
                            func.set_auto_instr_highlight(instr.address, HighlightStandardColor.OrangeHighlightColor)
                            found += 1
        log_info(f"[dotninja] Reflection scan found {found} dynamic invocations")
        return found

    @staticmethod
    def remove_opaque_predicates(bv, func):
        patches = 0
        undo_id = bv.begin_undo_actions()
        try:
            ssa = func.mlil.ssa_form
            for instr in ssa:
                if _op_name(instr) != "MLIL_IF":
                    continue
                value = _ssa_constant(instr.condition, ssa, deadline=time.monotonic() + 0.05)
                if value is None:
                    continue
                address = int(instr.address)
                raw = bv.read(address, 5)
                if not raw:
                    continue
                opcode = raw[0]
                replacement = None
                if bool(value) and 0x2C <= opcode <= 0x37:
                    replacement = b"\x2b"
                elif bool(value) and 0x39 <= opcode <= 0x44:
                    replacement = b"\x38"
                elif not bool(value) and 0x2C <= opcode <= 0x37:
                    replacement = b"\x00\x00"
                elif not bool(value) and 0x39 <= opcode <= 0x44:
                    replacement = b"\x00" * 5
                if replacement is not None and bv.write(address, replacement) == len(replacement):
                    patches += 1
                    log_info(f"[dotninja] Patched opaque predicate at {address:#x}")
            if patches:
                func.reanalyze()
        finally:
            bv.commit_undo_actions(undo_id)
        return patches

    @staticmethod
    def decrypt_strings(bv, func):
        recovered, skipped = 0, []
        ssa = func.mlil.ssa_form
        for instr in ssa:
            if _op_name(instr) not in {"MLIL_CALL_SSA", "MLIL_CALL"} or _op_name(instr.dest) != "MLIL_CONST_PTR":
                continue
            sym = bv.get_symbol_at(instr.dest.constant)
            if not sym or "decrypt" not in sym.name.lower():
                continue
            args = []
            for param in instr.params:
                value = _ssa_constant(param, ssa, deadline=time.monotonic() + 0.05)
                if value is None:
                    skipped.append({"address": instr.address, "reason": "non-static SSA argument"})
                    break
                args.append(value)
            else:
                programs = bv.session_data.get("dotninja.decryptors", {})
                program = programs.get(int(instr.dest.constant))
                if not program:
                    skipped.append({"address": instr.address, "reason": "decryptor body not in safe emulator form"})
                    continue
                try:
                    plaintext = emulate_pure_cil(program, args)
                except EmulationError as exc:
                    skipped.append({"address": instr.address, "reason": str(exc)})
                    continue
                if isinstance(plaintext, (str, bytes)):
                    if isinstance(plaintext, bytes):
                        plaintext = plaintext.decode("utf-8", errors="replace")
                    bv.set_comment_at(instr.address, f"Decrypted: {plaintext}")
                    recovered += 1
        bv.session_data["dotninja.decrypt_skips"] = skipped
        log_info(f"[dotninja] Recovered {recovered} strings; skipped {len(skipped)} candidates")
        return recovered

def register_plugins():
    PluginCommand.register("dotninja \\ Highlight Reflection & Unpackers", "Highlights dynamic managed API calls", DotNetAnalyzer.highlight_reflection)
    PluginCommand.register_for_function("dotninja \\ Remove Opaque Predicates (SSA)", "Evaluates SSA predicates and patches recognized CIL branches", DotNetAnalyzer.remove_opaque_predicates)
    PluginCommand.register_for_function("dotninja \\ Auto-Decrypt Strings", "Safely emulates bounded string decryptors", DotNetAnalyzer.decrypt_strings)
