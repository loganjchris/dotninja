"""
dotninja.arch
Phase 3 & 4: CIL Architecture & LLIL Parser (Restored & Stable)
"""

import struct
from typing import ClassVar, dict, Any

from binaryninja import (
    Architecture,
    BranchType,
    InstructionInfo,
    InstructionTextToken,
    InstructionTextTokenType,
    RegisterInfo,
)
from dncil.cil.opcode import OpCodes

# Dynamically crawl the OpCodes class to build our rapid byte-decoding dictionaries
_OPCODES_1 = {}
_OPCODES_2 = {}

for _name in dir(OpCodes):
    _op = getattr(OpCodes, _name)
    if hasattr(_op, "value") and hasattr(_op, "operand_type"):
        if _op.value <= 0xFF:
            _OPCODES_1[_op.value] = _op
        else:
            _OPCODES_2[_op.value & 0xFF] = _op


class DotNetArch(Architecture):
    """
    Custom DotNet Architecture implementation for Binary Ninja.
    Provides instruction decoding, basic block branching, text tokens, and low-level IL lifting.
    """

    name = "dotnet"

    address_size = 4
    default_int_size = 4
    instr_alignment = 1
    max_instr_length = 256

    regs: ClassVar[dict[str, Any]] = {
        "ip": RegisterInfo("ip", 4),  # type: ignore
        "sp": RegisterInfo("sp", 4),  # type: ignore
    }

    # Populate synthetic eval, local, and argument registers securely
    for _i in range(256):
        regs[f"eval_{_i}"] = RegisterInfo(f"eval_{_i}", 4)  # type: ignore
        regs[f"loc_{_i}"] = RegisterInfo(f"loc_{_i}", 4)  # type: ignore
        regs[f"arg_{_i}"] = RegisterInfo(f"arg_{_i}", 4)  # type: ignore

    stack_pointer = "sp"

    def _decode_instruction(self, data, addr):
        """Statelessly decodes a CIL instruction using dncil metadata"""
        if not data:
            return None, None, 0

        op_byte = data[0]
        opcode = None
        instr_len = 1

        if op_byte == 0xFE:
            if len(data) < 2:
                return None, None, 0
            opcode = _OPCODES_2.get(data[1])
            instr_len = 2
        else:
            opcode = _OPCODES_1.get(op_byte)

        if not opcode:
            return None, None, 0

        type_name = str(opcode.operand_type).split(".")[-1]
        operand_value = None
        op_size = 0
        fmt = ""

        if type_name in (
            "InlineBrTarget",
            "InlineI",
            "InlineString",
            "InlineMethod",
            "InlineField",
            "InlineType",
            "InlineTok",
            "InlineSig",
        ):
            op_size, fmt = 4, "<i" if type_name == "InlineBrTarget" else "<I"
        elif type_name in ("ShortInlineBrTarget", "ShortInlineI", "ShortInlineVar"):
            op_size, fmt = 1, "<b" if type_name == "ShortInlineBrTarget" else "<B"
        elif type_name == "InlineVar":
            op_size, fmt = 2, "<H"
        elif type_name in ("InlineI8", "InlineR"):
            op_size, fmt = 8, "<q" if type_name == "InlineI8" else "<d"
        elif type_name == "ShortInlineR":
            op_size, fmt = 4, "<f"
        elif type_name == "InlineSwitch":
            if len(data) >= instr_len + 4:
                count = struct.unpack("<I", data[instr_len : instr_len + 4])[0]
                op_size = 4 + (count * 4)
                operand_value = count
            else:
                return None, None, 0

        if op_size > 0 and type_name != "InlineSwitch":
            if len(data) < instr_len + op_size:
                return None, None, 0
            operand_value = struct.unpack(fmt, data[instr_len : instr_len + op_size])[0]

        instr_len += op_size
        return opcode, operand_value, instr_len

    def get_instruction_info(self, data, addr):
        """Phase 3: Translate CIL branching into Binary Ninja BranchTypes"""
        opcode, operand, length = self._decode_instruction(data, addr)
        info = InstructionInfo()
        info.length = length if length > 0 else 1

        if not opcode:
            return info

        name = opcode.name.lower()
        type_name = str(opcode.operand_type).split(".")[-1]
        safe_operand = operand if operand is not None else 0

        if name in ("br", "br.s", "leave", "leave.s"):
            info.add_branch(
                BranchType.UnconditionalBranch, addr + length + safe_operand
            )
        elif name in ("ret", "endfinally", "endfilter"):
            info.add_branch(BranchType.FunctionReturn, 0)
        elif name in ("throw", "rethrow"):
            pass
        elif name in ("call", "callvirt", "newobj"):
            if hasattr(self, "token_map") and safe_operand in self.token_map:
                target = int(self.token_map[safe_operand])
            else:
                target = int(0x50000000 + (safe_operand & 0x00FFFFFF) * 4)
            info.add_branch(BranchType.CallDestination, target)
        elif name == "calli":
            info.add_branch(BranchType.IndirectBranch, int(safe_operand))
        elif name == "switch":
            base_addr = addr + length
            for i in range(safe_operand):
                offset_idx = (length - (safe_operand * 4)) + (i * 4)
                if len(data) >= offset_idx + 4:
                    target_offset = struct.unpack(
                        "<i", data[offset_idx : offset_idx + 4]
                    )[0]
                    info.add_branch(
                        BranchType.IndirectBranch, int(base_addr + target_offset)
                    )
        elif name in (
            "brtrue",
            "brtrue.s",
            "brfalse",
            "brfalse.s",
            "beq",
            "beq.s",
            "bge",
            "bge.s",
            "bge.un",
            "bge.un.s",
            "bgt",
            "bgt.s",
            "bgt.un",
            "bgt.un.s",
            "ble",
            "ble.s",
            "ble.un",
            "ble.un.s",
            "blt",
            "blt.s",
            "blt.un",
            "blt.un.s",
            "bne.un",
            "bne.un.s",
        ):
            if name in ("brfalse", "brfalse.s"):
                info.add_branch(BranchType.TrueBranch, int(addr + length))
                info.add_branch(
                    BranchType.FalseBranch, int(addr + length + safe_operand)
                )
            else:
                info.add_branch(
                    BranchType.TrueBranch, int(addr + length + safe_operand)
                )
                info.add_branch(BranchType.FalseBranch, int(addr + length))

        return info

    def get_instruction_text(self, data, addr):
        """Phase 3: Emit styled UI tokens for the disassembler view"""
        opcode, operand, length = self._decode_instruction(data, addr)
        if not opcode:
            return [], 1

        tokens = [
            InstructionTextToken(InstructionTextTokenType.InstructionToken, opcode.name)
        ]
        if operand is not None:
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, " "))
            type_name = str(opcode.operand_type).split(".")[-1]

            if type_name in ("InlineBrTarget", "ShortInlineBrTarget"):
                target = addr + length + operand
                tokens.append(
                    InstructionTextToken(
                        InstructionTextTokenType.CodeRelativeAddressToken,
                        hex(target),
                        target,
                    )
                )
            elif type_name in (
                "InlineString",
                "InlineMethod",
                "InlineField",
                "InlineType",
                "InlineTok",
            ):
                tokens.append(
                    InstructionTextToken(
                        InstructionTextTokenType.IntegerToken,
                        f"0x{operand:08X}",
                        operand,
                    )
                )
            elif type_name == "InlineSwitch":
                tokens.append(
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, f"({operand} jump targets)"
                    )
                )
            elif "Var" in type_name:
                tokens.append(
                    InstructionTextToken(
                        InstructionTextTokenType.RegisterToken, f"V_{operand}"
                    )
                )
            elif type_name in ("ShortInlineR", "InlineR"):
                tokens.append(
                    InstructionTextToken(
                        InstructionTextTokenType.TextToken, f"{operand}"
                    )
                )
            else:
                tokens.append(
                    InstructionTextToken(
                        InstructionTextTokenType.IntegerToken,
                        hex(int(operand)),
                        operand,
                    )
                )

        return tokens, length

    def get_instruction_low_level_il(self, data, addr, il):
        """Phase 4: Delegate to our deterministic LLIL Lifter"""
        from .lifter import lift_instruction

        return lift_instruction(self, data, addr, il)
