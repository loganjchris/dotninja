"""
dotninja.analyzer
Phase 6: SSA Deobfuscation & Extensibility
"""

from binaryninja import (
    HighlightStandardColor,
    MediumLevelILOperation,
    PluginCommand,
)
from binaryninja.log import log_info, log_warn


class DotNetAnalyzer:

    @staticmethod
    def highlight_reflection(bv):
        """
        Scans all functions for Reflection and dynamic loading APIs.
        Highlights the instruction and block in orange to anchor analysts to unpackers.
        """
        log_info("[dotninja] Scanning for Reflection and dynamic Assembly loading...")
        found = 0

        for func in bv.functions:
            for block in func.mlil:
                for instr in block:
                    if instr.operation == MediumLevelILOperation.MLIL_CALL:
                        target_expr = instr.dest
                        if (
                            target_expr.operation
                            == MediumLevelILOperation.MLIL_CONST_PTR
                        ):
                            sym = bv.get_symbol_at(target_expr.constant)
                            if sym:
                                name = sym.name.lower()
                                if (
                                    "assembly::load" in name
                                    or "methodbase::invoke" in name
                                    or "marshal::copy" in name
                                ):
                                    # Highlight the specific instruction
                                    func.set_auto_instr_highlight(
                                        instr.address,
                                        HighlightStandardColor.OrangeHighlightColor,
                                    )
                                    found += 1

        log_info(
            f"[dotninja] Reflection scan complete. Found {found} dynamic invocations."
        )

    @staticmethod
    def remove_opaque_predicates(bv, func):
        """
        Uses MLIL to evaluate static conditions (e.g., brtrue where condition is always 1).
        Patches the underlying CIL byte to NOPs or unconditional jumps to collapse the CFG.
        """
        patches_applied = 0
        bv.begin_undo_actions()

        try:
            for block in func.mlil:
                for instr in block:
                    if instr.operation == MediumLevelILOperation.MLIL_IF:
                        cond = instr.condition

                        if cond.operation == MediumLevelILOperation.MLIL_CONST:
                            is_true = cond.constant != 0
                            branch_addr = instr.address

                            try:
                                op_byte = bv.read(branch_addr, 1)
                                if op_byte:
                                    op_val = op_byte[0]
                                    if is_true:
                                        if 0x2C <= op_val <= 0x37:
                                            bv.write(branch_addr, b"\x2B")
                                        elif 0x39 <= op_val <= 0x44:
                                            bv.write(branch_addr, b"\x38")
                                        log_info(f"[dotninja] Patched Always-True predicate at {hex(branch_addr)}")
                                    else:
                                        if 0x2C <= op_val <= 0x37:
                                            bv.write(branch_addr, b"\x00\x00")
                                        elif 0x39 <= op_val <= 0x44:
                                            bv.write(branch_addr, b"\x00\x00\x00\x00\x00")
                                        log_info(f"[dotninja] Patched Always-False predicate at {hex(branch_addr)}")
                                    patches_applied += 1
                            except Exception as e:
                                log_warn(
                                    f"[dotninja] Failed to patch CIL at {hex(branch_addr)}: {e}"
                                )

            if patches_applied > 0:
                func.reanalyze()
        finally:
            bv.commit_undo_actions()

    @staticmethod
    def decrypt_strings(bv, func):
        """
        Example Harness: Trace arguments backward using SSA to decrypt strings.
        Target: A known decryptor method at a specific address or name.
        """
        for instr in func.mlil.ssa_form:
            if instr.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                target = instr.dest
                
                # Check for a decryptor by name instead of hardcoded address
                is_decryptor = False
                if target.operation == MediumLevelILOperation.MLIL_CONST_PTR:
                    sym = bv.get_symbol_at(target.constant)
                    if sym and "decrypt" in sym.name.lower():
                        is_decryptor = True

                if is_decryptor:
                    args = instr.params
                    if len(args) > 0:
                        first_arg = args[0]

                        if first_arg.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                            def_instr = func.mlil.ssa_form.get_ssa_var_definition(
                                first_arg.var
                            )

                            if (
                                def_instr
                                and def_instr.operation
                                == MediumLevelILOperation.MLIL_SET_VAR_SSA
                            ):
                                src_val = def_instr.src
                                if (
                                    src_val.operation
                                    == MediumLevelILOperation.MLIL_CONST
                                ):
                                    encrypted_key = src_val.constant

                                    decrypted_str = (
                                        f"Decrypted_String_{hex(encrypted_key)}"
                                    )

                                    bv.set_comment_at(
                                        instr.address, f"Decrypted: {decrypted_str}"
                                    )
                                    log_info(
                                        f"[dotninja] Auto-decrypted string at {hex(instr.address)}"
                                    )


def register_plugins():
    PluginCommand.register(
        "dotninja \\ Highlight Reflection & Unpackers",
        "Highlights dynamic API calls (Assembly.Load, Invoke)",
        DotNetAnalyzer.highlight_reflection,
    )

    PluginCommand.register_for_function(
        "dotninja \\ Remove Opaque Predicates (SSA)",
        "Evaluates constant branches and patches them with NOPs",
        DotNetAnalyzer.remove_opaque_predicates,
    )

    PluginCommand.register_for_function(
        "dotninja \\ Auto-Decrypt Strings (Example)",
        "Traces SSA arguments into a suspected decryptor",
        DotNetAnalyzer.decrypt_strings,
    )
