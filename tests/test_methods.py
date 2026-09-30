import struct
import pytest
from methods import MethodBodyError, parse_method_body

def test_tiny_method_extent():
    body = parse_method_body(bytes([(3 << 2) | 2, 0x16, 0x2A, 0x00]))
    assert (body.header_size, body.code_size, body.total_size) == (1, 3, 4)

def test_fat_method_extent_and_locals():
    header = struct.pack("<HHII", 0x3003, 16, 2, 0x11000001)
    body = parse_method_body(header + b"\x16\x2a")
    assert body.max_stack == 16
    assert body.local_signature_token == 0x11000001
    assert body.total_size == 14

def test_truncated_body_rejected():
    with pytest.raises(MethodBodyError):
        parse_method_body(bytes([0x12, 0x2A]))
