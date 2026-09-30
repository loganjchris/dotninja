"""
dotninja.arch
Phase 3 & 4: CIL Architecture & LLIL Parser (Restored & Stable)
"""

import struct
from typing import Any, ClassVar

from binaryninja import (
    Architecture,
    BranchType,
    CallingConvention,
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


class _DotNetArchBase(Architecture):
    """
    Custom DotNet Architecture implementation for Binary Ninja.
    Provides instruction decoding, basic block branching, text tokens, and low-level IL lifting.
    """

    address_size = 4
    default_int_size = 4
    instr_alignment = 1
    max_instr_length = 256

    regs: ClassVar[dict[str, Any]] = {
        "ip": RegisterInfo("ip", 4),  # type: ignore
        "sp": RegisterInfo("sp", 4),  # type: ignore
        "ret": RegisterInfo("ret", 4),  # type: ignore
    }

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

        type_name = opcode.operand_type.name
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
                if len(data) < instr_len + op_size:
                    return None, None, 0
                operand_value = tuple(
                    struct.unpack_from("<i", data, instr_len + 4 + (index * 4))[0]
                    for index in range(count)
                )
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
        type_name = opcode.operand_type.name
        safe_operand = int(operand) if isinstance(operand, (int, float)) else 0

        if name in ("br", "br.s", "leave", "leave.s"):
            info.add_branch(
                BranchType.UnconditionalBranch, addr + length + safe_operand
            )
        elif name in ("ret", "endfinally", "endfilter"):
            info.add_branch(BranchType.FunctionReturn, 0)
        elif name in ("throw", "rethrow"):
            pass
        elif name in ("call", "callvirt", "newobj"):
            # View-local token targets are resolved by LLIL. Advertising a
            # synthetic architecture-level call target makes core analysis
            # create and disassemble fake external functions.
            pass
        elif name == "calli":
            info.add_branch(BranchType.IndirectBranch, int(safe_operand))
        elif name == "switch":
            base_addr = addr + length
            info.add_branch(BranchType.FalseBranch, base_addr)
            for target_offset in operand or ():
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
            type_name = opcode.operand_type.name

            if type_name in ("InlineBrTarget", "ShortInlineBrTarget"):
                target = addr + length + int(operand)
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
                        InstructionTextTokenType.TextToken,
                        "(" + ", ".join(hex(addr + length + offset) for offset in operand) + ")",
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


class DotNet32(_DotNetArchBase):
    name = "dotnet32"
    address_size = 4
    default_int_size = 4
    regs = {
        "ip": RegisterInfo("ip", 4),
        "sp": RegisterInfo("sp", 4),
        "ret": RegisterInfo("ret", 4),
    }


class DotNet64(_DotNetArchBase):
    name = "dotnet64"
    address_size = 8
    default_int_size = 8
    regs = {
        "ip": RegisterInfo("ip", 8),
        "sp": RegisterInfo("sp", 8),
        "ret": RegisterInfo("ret", 8),
    }


class DotNetCallingConvention(CallingConvention):
    """Stack-parameter convention for managed CIL methods."""

    int_arg_regs: list[str] = []
    float_arg_regs: list[str] = []
    int_return_reg = "ret"
    caller_saved_regs = ["ret"]


# Backwards-compatible import name. New views select an explicit width.
DotNetArch = DotNet32


def decode_instruction(data, addr=0):
    """Decode without relying on Binary Ninja's CoreArchitecture wrapper."""
    return _DotNetArchBase._decode_instruction(None, data, addr)
