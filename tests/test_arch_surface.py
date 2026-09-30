from pathlib import Path
from types import SimpleNamespace

import dnfile
from binaryninja import LowLevelILFunction

from dotninja.arch import DotNet32, DotNet64, decode_instruction
from dotninja.methods import parse_method_body
from dotninja.view import external_slot_address, parse_compressed_uint


def test_terminal_lifting_uses_supported_binary_ninja_api():
    assert hasattr(LowLevelILFunction, "trap")
    assert not hasattr(LowLevelILFunction, "no_return")

def test_architecture_register_width_matches_managed_pointer_width():
    assert DotNet32.regs["sp"].size == 4
    assert DotNet32.regs["ret"].size == 4
    assert DotNet64.regs["sp"].size == 8
    assert DotNet64.regs["ret"].size == 8

def test_external_slots_use_native_pointer_width():
    assert external_slot_address(0x50001000, 3, 4) == 0x5000100C
    assert external_slot_address(0x50001000, 3, 8) == 0x50001018

def test_ecma_compressed_unsigned_integer_widths():
    assert parse_compressed_uint(bytes([0x7F])) == (0x7F, 1)
    assert parse_compressed_uint(bytes([0x92, 0x34])) == (0x1234, 2)
    assert parse_compressed_uint(bytes([0xC1, 0x23, 0x45, 0x67])) == (0x01234567, 4)

def test_switch_decoder_preserves_signed_case_offsets():
    data = bytes.fromhex("45 02 00 00 00 04 00 00 00 f8 ff ff ff")
    opcode, offsets, length = decode_instruction(data, 0x1000)
    assert opcode.name.lower() == "switch"
    assert offsets == (4, -8)
    assert length == len(data)
    info = DotNet32.get_instruction_info(SimpleNamespace(_decode_instruction=decode_instruction), data, 0x1000)
    assert info.length == len(data)
    assert len(info.branches) == 3


def test_fixture_instruction_text_and_info_are_consistent():
    root = Path(__file__).parents[1] / "fixtures"
    architecture = SimpleNamespace(_decode_instruction=decode_instruction)
    for path in root.glob("fixture-*.exe"):
        data = path.read_bytes()
        pe = dnfile.dnPE(data=data)
        assert pe.net is not None and pe.net.mdtables is not None
        method_defs = pe.net.mdtables.MethodDef
        assert method_defs is not None
        for row in method_defs:
            if not int(row.Rva):
                continue
            file_offset = pe.get_offset_from_rva(int(row.Rva))
            body = parse_method_body(data[file_offset:])
            cursor = file_offset + body.header_size
            end = cursor + body.code_size
            while cursor < end:
                opcode, _, length = decode_instruction(data[cursor:end], cursor)
                info = DotNet32.get_instruction_info(architecture, data[cursor:end], cursor)
                text, text_length = DotNet32.get_instruction_text(architecture, data[cursor:end], cursor)
                assert opcode is not None and text
                assert length == text_length == info.length
                cursor += length
