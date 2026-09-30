"""Pure ECMA-335 signature parsing used by the loader, lifter, and tests."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Callable


class ElementType(IntEnum):
    END = 0x00
    VOID = 0x01
    BOOLEAN = 0x02
    CHAR = 0x03
    I1 = 0x04
    U1 = 0x05
    I2 = 0x06
    U2 = 0x07
    I4 = 0x08
    U4 = 0x09
    I8 = 0x0A
    U8 = 0x0B
    R4 = 0x0C
    R8 = 0x0D
    STRING = 0x0E
    PTR = 0x0F
    BYREF = 0x10
    VALUETYPE = 0x11
    CLASS = 0x12
    VAR = 0x13
    ARRAY = 0x14
    GENERICINST = 0x15
    TYPEDBYREF = 0x16
    I = 0x18
    U = 0x19
    FNPTR = 0x1B
    OBJECT = 0x1C
    SZARRAY = 0x1D
    MVAR = 0x1E
    CMOD_REQD = 0x1F
    CMOD_OPT = 0x20
    SENTINEL = 0x41
    PINNED = 0x45


@dataclass(frozen=True)
class CilType:
    element: ElementType
    token: int | None = None
    inner: "CilType | None" = None
    generic_args: tuple["CilType", ...] = ()
    rank: int = 0

    @property
    def is_void(self) -> bool:
        return self.element == ElementType.VOID


@dataclass(frozen=True)
class MethodSignature:
    calling_convention: int
    has_this: bool
    explicit_this: bool
    generic_parameter_count: int
    return_type: CilType
    parameters: tuple[CilType, ...]
    sentinel_index: int | None = None


@dataclass(frozen=True)
class FieldSignature:
    field_type: CilType


@dataclass(frozen=True)
class LocalSignature:
    locals: tuple[CilType, ...]


class SignatureError(ValueError):
    pass


class _Reader:
    def __init__(self, data: bytes):
        self.data = bytes(data)
        self.offset = 0

    def byte(self) -> int:
        if self.offset >= len(self.data):
            raise SignatureError("truncated signature")
        value = self.data[self.offset]
        self.offset += 1
        return value

    def compressed_uint(self) -> int:
        first = self.byte()
        if first & 0x80 == 0:
            return first
        if first & 0xC0 == 0x80:
            return ((first & 0x3F) << 8) | self.byte()
        if first & 0xE0 == 0xC0:
            return (
                ((first & 0x1F) << 24)
                | (self.byte() << 16)
                | (self.byte() << 8)
                | self.byte()
            )
        raise SignatureError("reserved compressed integer encoding")


def _coded_type_token(value: int) -> int:
    tag = value & 3
    rid = value >> 2
    tables = {0: 0x02, 1: 0x01, 2: 0x1B}
    if tag not in tables or rid == 0:
        raise SignatureError("invalid TypeDefOrRef coded index")
    return (tables[tag] << 24) | rid


def _parse_type(reader: _Reader) -> CilType:
    raw = reader.byte()
    try:
        element = ElementType(raw)
    except ValueError as exc:
        raise SignatureError(f"unsupported element type 0x{raw:02x}") from exc
    if element in (ElementType.CMOD_REQD, ElementType.CMOD_OPT):
        reader.compressed_uint()
        return _parse_type(reader)
    if element == ElementType.PINNED:
        return CilType(element, inner=_parse_type(reader))
    if element in (ElementType.PTR, ElementType.BYREF, ElementType.SZARRAY):
        return CilType(element, inner=_parse_type(reader))
    if element in (ElementType.CLASS, ElementType.VALUETYPE):
        return CilType(element, token=_coded_type_token(reader.compressed_uint()))
    if element in (ElementType.VAR, ElementType.MVAR):
        return CilType(element, token=reader.compressed_uint())
    if element == ElementType.ARRAY:
        inner = _parse_type(reader)
        rank = reader.compressed_uint()
        sizes = reader.compressed_uint()
        for _ in range(sizes):
            reader.compressed_uint()
        lower_bounds = reader.compressed_uint()
        for _ in range(lower_bounds):
            reader.compressed_uint()
        return CilType(element, inner=inner, rank=rank)
    if element == ElementType.GENERICINST:
        kind = ElementType(reader.byte())
        if kind not in (ElementType.CLASS, ElementType.VALUETYPE):
            raise SignatureError("invalid generic instance kind")
        token = _coded_type_token(reader.compressed_uint())
        count = reader.compressed_uint()
        return CilType(
            element,
            token=token,
            inner=CilType(kind, token=token),
            generic_args=tuple(_parse_type(reader) for _ in range(count)),
        )
    if element == ElementType.FNPTR:
        parse_method_signature_from_reader(reader)
    return CilType(element)


def parse_method_signature_from_reader(reader: _Reader) -> MethodSignature:
    callconv = reader.byte()
    generic_count = reader.compressed_uint() if callconv & 0x10 else 0
    parameter_count = reader.compressed_uint()
    return_type = _parse_type(reader)
    parameters: list[CilType] = []
    sentinel_index = None
    while len(parameters) < parameter_count:
        if reader.offset < len(reader.data) and reader.data[reader.offset] == ElementType.SENTINEL:
            reader.offset += 1
            sentinel_index = len(parameters)
        parameters.append(_parse_type(reader))
    return MethodSignature(
        callconv,
        bool(callconv & 0x20),
        bool(callconv & 0x40),
        generic_count,
        return_type,
        tuple(parameters),
        sentinel_index,
    )


def parse_method_signature(data: bytes) -> MethodSignature:
    return parse_method_signature_from_reader(_Reader(data))


def parse_field_signature(data: bytes) -> FieldSignature:
    reader = _Reader(data)
    if reader.byte() != 0x06:
        raise SignatureError("not a field signature")
    return FieldSignature(_parse_type(reader))


def parse_local_signature(data: bytes) -> LocalSignature:
    reader = _Reader(data)
    if reader.byte() != 0x07:
        raise SignatureError("not a local signature")
    return LocalSignature(tuple(_parse_type(reader) for _ in range(reader.compressed_uint())))


def parse_member_signature(data: bytes) -> MethodSignature | FieldSignature:
    if not data:
        raise SignatureError("empty signature")
    return parse_field_signature(data) if data[0] == 0x06 else parse_method_signature(data)


def native_width(cil_type: CilType, pointer_size: int) -> int:
    widths = {
        ElementType.BOOLEAN: 1, ElementType.I1: 1, ElementType.U1: 1,
        ElementType.CHAR: 2, ElementType.I2: 2, ElementType.U2: 2,
        ElementType.I4: 4, ElementType.U4: 4, ElementType.R4: 4,
        ElementType.I8: 8, ElementType.U8: 8, ElementType.R8: 8,
    }
    return widths.get(cil_type.element, pointer_size)


def stack_effect(signature: MethodSignature, opcode: str) -> tuple[int, int]:
    pops = len(signature.parameters)
    if signature.has_this and opcode != "newobj":
        pops += 1
    if opcode == "calli":
        pops += 1
    pushes = 1 if opcode == "newobj" or not signature.return_type.is_void else 0
    return pops, pushes
