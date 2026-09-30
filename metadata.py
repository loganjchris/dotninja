"""CLR metadata resolution and parsed, view-owned token targets."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from binaryninja.log import log_warn
from .signatures import FieldSignature, MethodSignature, parse_field_signature, parse_member_signature, parse_method_signature

@dataclass(frozen=True)
class TokenTarget:
    token: int
    kind: str
    address: int | None
    name: str
    signature: MethodSignature | FieldSignature | None = None

def _blob_bytes(value: Any) -> bytes:
    value_bytes = getattr(value, "value_bytes", None)
    if callable(value_bytes):
        return bytes(value_bytes())
    value = getattr(value, "value", value)
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    try:
        return bytes(value)
    except (TypeError, ValueError):
        return b""

class MetadataResolver:
    def __init__(self, pe):
        self.pe = pe
        self.method_to_class: dict[int, Any] = {}
        self.field_to_class: dict[int, Any] = {}
        self.targets: dict[int, TokenTarget] = {}
        self._build_owner_maps()

    @property
    def tables(self):
        return getattr(getattr(self.pe, "net", None), "mdtables", None)

    def _build_owner_maps(self):
        type_defs = getattr(self.tables, "TypeDef", None) if self.tables else None
        for owner in type_defs or ():
            for row in getattr(owner, "MethodList", ()) or ():
                if getattr(row, "row_index", None):
                    self.method_to_class[int(row.row_index) - 1] = owner
            for row in getattr(owner, "FieldList", ()) or ():
                if getattr(row, "row_index", None):
                    self.field_to_class[int(row.row_index) - 1] = owner

    @staticmethod
    def _qualified_type(row) -> str:
        name = str(getattr(row, "TypeName", "") or "")
        namespace = str(getattr(row, "TypeNamespace", "") or "")
        return f"{namespace}.{name}" if namespace else name

    def get_method_full_name(self, index: int) -> str:
        rows = getattr(self.tables, "MethodDef", None) if self.tables else None
        if not rows or not 0 <= index < len(rows):
            return f"method_0x{index + 1:x}"
        name = str(getattr(rows[index], "Name", "") or f"method_0x{index + 1:x}")
        owner = self.method_to_class.get(index)
        return f"{self._qualified_type(owner)}::{name}" if owner else name

    def get_field_full_name(self, index: int) -> str:
        rows = getattr(self.tables, "Field", None) if self.tables else None
        if not rows or not 0 <= index < len(rows):
            return f"field_0x{index + 1:x}"
        name = str(getattr(rows[index], "Name", "") or f"field_0x{index + 1:x}")
        owner = self.field_to_class.get(index)
        return f"{self._qualified_type(owner)}::{name}" if owner else name

    def method_signature(self, row) -> MethodSignature | None:
        try:
            return parse_method_signature(_blob_bytes(getattr(row, "Signature", None)))
        except (ValueError, TypeError) as exc:
            log_warn(f"[dotninja] Invalid method signature: {exc}")
            return None

    def field_signature(self, row) -> FieldSignature | None:
        try:
            return parse_field_signature(_blob_bytes(getattr(row, "Signature", None)))
        except (ValueError, TypeError) as exc:
            log_warn(f"[dotninja] Invalid field signature: {exc}")
            return None

    def member_signature(self, row) -> MethodSignature | FieldSignature | None:
        try:
            return parse_member_signature(_blob_bytes(getattr(row, "Signature", None)))
        except (ValueError, TypeError) as exc:
            log_warn(f"[dotninja] Invalid member signature: {exc}")
            return None

    def _member_owner_name(self, row) -> str:
        owner = getattr(row, "Class", None)
        # dnfile coded-index objects expose the resolved row directly. Prefer
        # it because recent dnfile versions do not populate table_index.
        resolved_owner = getattr(owner, "row", None)
        if resolved_owner is not None:
            qualified = self._qualified_type(resolved_owner)
            if qualified:
                return qualified
        table_index = getattr(owner, "table_index", None)
        index = int(getattr(owner, "row_index", 0) or 0) - 1
        table_name = {1: "TypeRef", 2: "TypeDef", 0x1B: "TypeSpec"}.get(table_index)
        rows = getattr(self.tables, table_name, None) if table_name and self.tables else None
        return self._qualified_type(rows[index]) if rows and 0 <= index < len(rows) else ""

    def register_target(self, target: TokenTarget) -> TokenTarget:
        self.targets[target.token] = target
        return target

    def resolve_target(self, token: int) -> TokenTarget | None:
        if token in self.targets:
            return self.targets[token]
        table, index = token >> 24, (token & 0xFFFFFF) - 1
        if index < 0:
            return None
        try:
            if table == 0x70:
                item = self.pe.net.user_strings.get(token & 0xFFFFFF)
                value = getattr(item, "value", item)
                if isinstance(value, bytes):
                    value = value.decode("utf-16-le", errors="replace")
                return TokenTarget(token, "string", None, str(value or ""))
            if table == 0x06:
                rows = getattr(self.tables, "MethodDef", None)
                if rows and index < len(rows):
                    return TokenTarget(token, "method", None, self.get_method_full_name(index), self.method_signature(rows[index]))
            if table == 0x04:
                rows = getattr(self.tables, "Field", None)
                if rows and index < len(rows):
                    return TokenTarget(token, "field", None, self.get_field_full_name(index), self.field_signature(rows[index]))
            if table == 0x0A:
                rows = getattr(self.tables, "MemberRef", None)
                if rows and index < len(rows):
                    row, signature = rows[index], self.member_signature(rows[index])
                    kind = "field" if isinstance(signature, FieldSignature) else "method"
                    owner, name = self._member_owner_name(row), str(getattr(row, "Name", "") or f"member_0x{index + 1:x}")
                    return TokenTarget(token, kind, None, f"{owner}::{name}" if owner else name, signature)
            if table in (1, 2):
                rows = getattr(self.tables, "TypeRef" if table == 1 else "TypeDef", None)
                if rows and index < len(rows):
                    return TokenTarget(token, "type", None, self._qualified_type(rows[index]))
        except (AttributeError, IndexError, TypeError, ValueError) as exc:
            log_warn(f"[dotninja] Failed token 0x{token:08x}: {exc}")
        return None

    def resolve_token(self, token: int) -> str | None:
        target = self.resolve_target(token)
        if not target:
            return None
        return f'"{target.name}"' if target.kind == "string" else target.name
