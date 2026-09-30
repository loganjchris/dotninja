"""Exact CIL method-body parsing independent of Binary Ninja."""

from __future__ import annotations

from dataclasses import dataclass
import struct


class MethodBodyError(ValueError):
    pass


@dataclass(frozen=True)
class ExceptionRegion:
    flags: int
    try_offset: int
    try_length: int
    handler_offset: int
    handler_length: int
    class_token_or_filter_offset: int


@dataclass(frozen=True)
class MethodBodyInfo:
    header_size: int
    code_size: int
    max_stack: int
    local_signature_token: int
    flags: int
    total_size: int
    exception_regions: tuple[ExceptionRegion, ...]

    @property
    def code_offset(self) -> int:
        return self.header_size


def parse_method_body(data: bytes) -> MethodBodyInfo:
    if not data:
        raise MethodBodyError("empty method body")
    kind = data[0] & 3
    if kind == 2:
        code_size = data[0] >> 2
        if len(data) < 1 + code_size:
            raise MethodBodyError("truncated tiny method")
        return MethodBodyInfo(1, code_size, 8, 0, 2, 1 + code_size, ())
    if kind != 3 or len(data) < 12:
        raise MethodBodyError("invalid fat method header")
    flags_size, max_stack, code_size, local_token = struct.unpack_from("<HHII", data)
    header_size = (flags_size >> 12) * 4
    flags = flags_size & 0x0FFF
    if header_size < 12 or header_size > len(data) or header_size + code_size > len(data):
        raise MethodBodyError("invalid fat method extent")
    cursor = header_size + code_size
    regions: list[ExceptionRegion] = []
    if flags & 0x08:
        cursor = (cursor + 3) & ~3
        more = True
        while more:
            if cursor + 4 > len(data):
                raise MethodBodyError("truncated exception section")
            section_kind = data[cursor]
            more = bool(section_kind & 0x80)
            fat = bool(section_kind & 0x40)
            if section_kind & 1 == 0:
                raise MethodBodyError("unknown extra section")
            if fat:
                size = int.from_bytes(data[cursor + 1:cursor + 4], "little")
                if size < 4 or size % 24:
                    raise MethodBodyError("invalid fat exception section")
                end = cursor + size
                if end > len(data):
                    raise MethodBodyError("truncated fat exception section")
                for off in range(cursor + 4, end, 24):
                    regions.append(ExceptionRegion(*struct.unpack_from("<IIIIII", data, off)))
            else:
                size = data[cursor + 1]
                if size < 4 or (size - 4) % 12:
                    raise MethodBodyError("invalid small exception section")
                end = cursor + size
                if end > len(data):
                    raise MethodBodyError("truncated small exception section")
                for off in range(cursor + 4, end, 12):
                    eflags, try_off, try_len, handler_off, handler_len, token = struct.unpack_from("<HHBHB I", data, off)
                    regions.append(ExceptionRegion(eflags, try_off, try_len, handler_off, handler_len, token))
            cursor = (end + 3) & ~3
    return MethodBodyInfo(header_size, code_size, max_stack, local_token, flags, cursor, tuple(regions))
