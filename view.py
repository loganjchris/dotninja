"""
dotninja.view
Phase 2 & 5: Fault-Tolerant .NET BinaryView (CLR)
Includes strict type sanitization and per-phase exception isolation.
"""

import hashlib
import struct

import dnfile
from binaryninja import (
    Architecture,
    BinaryView,
    SectionSemantics,
    SegmentFlag,
    Symbol,
    SymbolType,
    Type,
)
from binaryninja.log import log_error, log_info, log_warn

from .metadata import MetadataResolver, TokenTarget
from .methods import MethodBodyError, parse_method_body
from .signatures import ElementType, MethodSignature, native_width


def external_slot_address(base, index, pointer_size):
    """Return a non-overlapping native-width slot in the synthetic extern table."""
    return int(base) + (int(index) * int(pointer_size))


def parse_compressed_uint(data, offset=0):
    """Decode an ECMA-335 compressed unsigned integer."""
    first = data[offset]
    if first & 0x80 == 0:
        return first, 1
    if first & 0xC0 == 0x80:
        if offset + 2 > len(data):
            raise ValueError("truncated compressed integer")
        return ((first & 0x3F) << 8) | data[offset + 1], 2
    if first & 0xE0 == 0xC0:
        if offset + 4 > len(data):
            raise ValueError("truncated compressed integer")
        return (
            ((first & 0x1F) << 24)
            | (data[offset + 1] << 16)
            | (data[offset + 2] << 8)
            | data[offset + 3],
            4,
        )
    raise ValueError("invalid compressed integer")


class DotNetView(BinaryView):
    name = "DotNet"
    long_name = ".NET Managed Executable (CLR)"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.arch = Architecture["dotnet32"]
        self.platform = self.arch.standalone_platform
        self.pe = None
        self.metadata_resolver = None
        self._image_base = 0x400000

    @classmethod
    def is_valid_for_data(cls, data):
        if data.view_type != "Raw":
            return False

        try:
            header = data.read(0, min(int(data.length), 0x10000))
            if len(header) < 0x40 or header[:2] != b"MZ":
                return False
            pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
            if pe_offset + 24 > len(header) or header[pe_offset:pe_offset + 4] != b"PE\0\0":
                return False
            optional_size = struct.unpack_from("<H", header, pe_offset + 20)[0]
            optional = pe_offset + 24
            if optional + optional_size > len(header):
                return False
            magic = struct.unpack_from("<H", header, optional)[0]
            directory = optional + (112 if magic == 0x20B else 96)
            if magic not in (0x10B, 0x20B) or directory + (15 * 8) > optional + optional_size:
                return False
            clr_rva, clr_size = struct.unpack_from("<II", header, directory + 14 * 8)
            return clr_rva != 0 and clr_size >= 0x48
        except (IndexError, struct.error, TypeError, ValueError) as exc:
            log_warn(f"[dotninja] CLR header validation failed: {exc}")
            return False

    def init(self):
        try:
            raw_bytes = self.parent_view.read(0, self.parent_view.length)
            self.pe = dnfile.dnPE(data=raw_bytes)
            if not getattr(self.pe, "net", None) or not getattr(self.pe.net, "mdtables", None):
                raise ValueError("required CLR metadata tables are unavailable")
            self.metadata_resolver = MetadataResolver(self.pe)

            self.session_data["token_map"] = {}
            self.session_data["token_targets"] = {}
            self.session_data["method_bodies"] = {}
            self.session_data["method_signatures"] = {}
            self.session_data["dotninja.original_sha256"] = hashlib.sha256(raw_bytes).hexdigest()

            if hasattr(self.pe, "OPTIONAL_HEADER") and hasattr(
                self.pe.OPTIONAL_HEADER, "ImageBase"
            ):
                self._image_base = int(self.pe.OPTIONAL_HEADER.ImageBase)

            is_64 = getattr(self.pe, "PE_TYPE", None) == 0x20B
            self.arch = Architecture["dotnet64" if is_64 else "dotnet32"]
            self.platform = self.arch.standalone_platform

            # Layout and method ownership are required. A half-initialized view is unsafe.
            self._map_sections(raw_bytes)
            self._map_external_segment()
            self._parse_methods(raw_bytes)
            self._map_entry_point()
            for phase_name, phase_func in [
                ("P/Invoke Mapping", self._map_pinvokes),
                ("Type Reconstruction", self._reconstruct_types),
                ("Instruction Enrichment", self._enrich_instructions),
            ]:
                try:
                    phase_func()
                except Exception as phase_err:
                    log_warn(
                        f"[dotninja] Non-fatal exception during {phase_name}: {phase_err}"
                    )

            # Core analysis may inspect a function as soon as it is created.
            # Reassert CLR prototypes after every loader phase has completed so
            # early native-width inference cannot survive in MLIL/HLIL.
            self._apply_method_types()

            log_info(
                f"[dotninja] DotNetView initialized successfully for {self.file.filename}"
            )
            from .validation import arm_automatic_validation
            arm_automatic_validation(self)
            return True
        except Exception as e:
            log_error(f"[dotninja] Critical failure initializing DotNetView: {e}")
            return False

    def _safe_define_symbol(self, sym_type, addr, name):
        """Helper to create and define auto symbols safely with isolated error handling."""
        try:
            safe_addr = int(addr)
            safe_name = str(name if name else f"sym_{safe_addr:x}")
            sym = Symbol(sym_type, safe_addr, safe_name)
            self.define_auto_symbol(sym)
            return sym
        except Exception as e:
            log_warn(
                f"[dotninja] Could not define symbol '{name}' at {hex(int(addr))}: {e}"
            )
            return None

    def _bn_type(self, cil_type):
        if cil_type.element == ElementType.VOID:
            return Type.void()
        if cil_type.element in (ElementType.R4, ElementType.R8):
            return Type.float(native_width(cil_type, self.arch.address_size))
        if cil_type.element in (ElementType.BOOLEAN, ElementType.CHAR, ElementType.I1, ElementType.U1, ElementType.I2, ElementType.U2, ElementType.I4, ElementType.U4, ElementType.I8, ElementType.U8):
            signed = cil_type.element in (ElementType.I1, ElementType.I2, ElementType.I4, ElementType.I8)
            return Type.int(native_width(cil_type, self.arch.address_size), signed)
        if cil_type.element == ElementType.STRING:
            return Type.pointer(self.arch, Type.int(2, False))
        return Type.pointer(self.arch, Type.void())

    def _bn_function_type(self, signature, constructor=False):
        if not isinstance(signature, MethodSignature):
            return None
        params = [(f"arg{i}", self._bn_type(item)) for i, item in enumerate(signature.parameters)]
        if signature.has_this and not constructor:
            params.insert(0, ("this", Type.pointer(self.arch, Type.void())))
        return Type.function(
            Type.pointer(self.arch, Type.void())
            if constructor else self._bn_type(signature.return_type),
            params,
            calling_convention=self.arch.default_calling_convention,
            variable_arguments=signature.sentinel_index is not None,
        )

    def _materialize_external(self, address, name, signature=None):
        """Create a renderable extern-table entry without creating code."""
        # CIL newobj consumes only declared parameters and produces the newly
        # allocated reference. Model external constructors as factories at the
        # synthetic ABI boundary so call parameter and return inference agree.
        function_type = self._bn_function_type(
            signature, constructor=str(name).endswith("::.ctor")
        )
        pointee = function_type if function_type is not None else Type.void()
        self.define_data_var(
            int(address),
            Type.pointer(self.arch, pointee),
        )
        self.session_data.setdefault("extern_entries", {})[int(address)] = {
            "name": str(name),
            "kind": "function" if function_type is not None else "data",
        }

    def _map_sections(self, raw_bytes):
        base_addr = int(self._image_base)
        header_size = min(
            int(getattr(self.pe.OPTIONAL_HEADER, "SizeOfHeaders", 0) or 0),
            len(raw_bytes),
        )
        if header_size <= 0:
            raise ValueError("PE SizeOfHeaders is invalid")
        self.add_auto_segment(
            base_addr, header_size, 0, header_size, int(SegmentFlag.SegmentReadable)
        )

        for section in self.pe.sections:
            vaddr = int(base_addr + section.VirtualAddress)
            vsize = max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
            raw_size = int(section.SizeOfRawData)
            raw_ptr = int(section.PointerToRawData)
            file_length = max(0, min(raw_size, len(raw_bytes) - raw_ptr))

            flags = int(SegmentFlag.SegmentReadable)
            if section.Characteristics & 0x80000000:
                flags |= int(SegmentFlag.SegmentWritable)

            self.add_auto_segment(vaddr, vsize, raw_ptr, file_length, flags)

            sec_name = str(section.Name.decode("utf-8", errors="ignore").strip("\x00"))
            if section.Characteristics & 0x80000000:
                semantics = SectionSemantics.ReadWriteDataSectionSemantics
            elif section.Characteristics & 0x20000000:
                # Managed PE .text is a container for method headers, IL,
                # metadata and padding. Exact IL spans receive executable
                # segments below; the broad container must not claim all of
                # those bytes are code.
                semantics = SectionSemantics.ReadOnlyDataSectionSemantics
            else:
                semantics = SectionSemantics.ReadOnlyDataSectionSemantics
            # The managed PE .text section is only a physical container. Its
            # exact CIL and CLR heap regions are published below; adding the
            # container too would create overlapping pseudo-subsections.
            if sec_name != ".text":
                self.add_user_section(sec_name, vaddr, vsize, semantics)

        metadata = getattr(getattr(self.pe, "net", None), "metadata", None)
        for raw_name, stream in getattr(metadata, "streams", {}).items():
            name = raw_name.decode("ascii", errors="replace") if isinstance(raw_name, bytes) else str(raw_name)
            if name not in {"#~", "#-", "#Strings", "#US", "#Blob", "#GUID"}:
                continue
            address, length = base_addr + int(stream.rva), int(stream.sizeof())
            self.add_user_section(
                f".clr{name}", address, length,
                SectionSemantics.ReadOnlyDataSectionSemantics,
            )
            if name == "#US":
                self._define_user_string_heap(address, length)

    def _define_user_string_heap(self, address, length):
        """Bound #US strings so core string analysis cannot cross heap limits."""
        heap = self.read(int(address), int(length))
        cursor = 1  # ECMA-335 heaps reserve offset zero.
        while cursor < len(heap):
            try:
                byte_length, prefix_length = parse_compressed_uint(heap, cursor)
            except (IndexError, ValueError):
                break
            payload = cursor + prefix_length
            end = payload + byte_length
            if byte_length == 0 or end > len(heap):
                break
            char_count = max(0, (byte_length - 1) // 2)
            if char_count:
                string_address = int(address) + payload
                self.define_data_var(
                    string_address,
                    Type.array(Type.wide_char(2), char_count),
                )
                text = bytes(heap[payload:payload + char_count * 2]).decode(
                    "utf-16-le", errors="replace"
                )
                token = 0x70000000 | cursor
                target = TokenTarget(token, "string", string_address, text, None)
                self.metadata_resolver.register_target(target)
                self.session_data["token_map"][token] = string_address
                self.session_data["token_targets"][token] = target
            cursor = end

    def _apply_method_types(self):
        for address, signature in self.session_data.get("method_signatures", {}).items():
            function_type = self._bn_function_type(signature)
            if function_type is None:
                continue
            function = self.get_function_at(int(address), self.platform)
            if function is not None:
                function.set_user_type(function_type)

    def _map_pinvokes(self):
        mdtables = (
            getattr(self.pe.net, "mdtables", None)
            if hasattr(self.pe, "net") and self.pe.net
            else None
        )
        if not mdtables:
            return

        impl_map = getattr(mdtables, "ImplMap", None)
        method_def = getattr(mdtables, "MethodDef", None)
        module_ref = getattr(mdtables, "ModuleRef", None)

        if not impl_map or not method_def or not module_ref:
            return

        extern_base = 0x50000000

        slot_index = 0
        libraries = {}
        for impl_row in impl_map:
            try:
                method_idx = int(impl_row.MemberForwarded.row_index) - 1
                if 0 <= method_idx < len(method_def):
                    mod_idx = int(impl_row.ImportScope.row_index) - 1
                    if 0 <= mod_idx < len(module_ref):
                        dll_name = str(module_ref[mod_idx].Name)
                        import_name = str(impl_row.ImportName)

                        target_vaddr = external_slot_address(
                            extern_base, slot_index, self.arch.address_size
                        )
                        sym_name = f"{dll_name}!{import_name}"

                        library = libraries.get(dll_name)
                        if library is None:
                            library = self.add_external_library(dll_name, auto=True)
                            libraries[dll_name] = library
                        symbol = self._safe_define_symbol(
                            SymbolType.ImportedFunctionSymbol,
                            target_vaddr,
                            sym_name,
                        )
                        if symbol:
                            self.add_external_location(symbol, library, import_name, None, auto=True)

                        signature = self.metadata_resolver.method_signature(method_def[method_idx])
                        self._materialize_external(target_vaddr, sym_name, signature)

                        token = 0x06000000 | (method_idx + 1)
                        target = TokenTarget(token, "import", target_vaddr, sym_name, signature)
                        self.metadata_resolver.register_target(target)
                        self.session_data["token_map"][token] = target_vaddr
                        self.session_data["token_targets"][token] = target

                        slot_index += 1
            except Exception as e:
                log_warn(f"[dotninja] Skipping P/Invoke import entry due to error: {e}")

    def _map_external_segment(self):
        """Provide executable backing before any synthetic import functions are added."""
        self.add_auto_segment(
            0x50000000,
            0x2000,
            0,
            0,
            int(SegmentFlag.SegmentReadable),
        )
        self.add_user_section(
            ".extern", 0x50000000, 0x2000,
            SectionSemantics.ExternalSectionSemantics,
        )

    def _parse_methods(self, raw_bytes):
        mdtables = (
            getattr(self.pe.net, "mdtables", None)
            if hasattr(self.pe, "net") and self.pe.net
            else None
        )
        method_def = getattr(mdtables, "MethodDef", None) if mdtables else None
        if not method_def:
            raise ValueError("required MethodDef table is unavailable")

        candidates = parsed = 0
        for row_index, method_row in enumerate(method_def):
            try:
                rva = int(method_row.Rva)
                if rva == 0:
                    continue
                candidates += 1

                file_offset = self.pe.get_offset_from_rva(rva)
                if file_offset is None or file_offset >= len(raw_bytes):
                    continue

                body = parse_method_body(raw_bytes[file_offset:])
                header_size = body.header_size

                il_start_vaddr = int(self._image_base + rva + header_size)
                sym_name = str(self.metadata_resolver.get_method_full_name(row_index))

                signature = self.metadata_resolver.method_signature(method_row)
                token = 0x06000000 | (row_index + 1)
                self.session_data["token_map"][token] = il_start_vaddr
                target = TokenTarget(token, "method", il_start_vaddr, sym_name, signature)
                self.metadata_resolver.register_target(target)
                self.session_data["token_targets"][token] = target
                self.session_data["method_bodies"][il_start_vaddr] = body
                self.session_data["method_signatures"][il_start_vaddr] = signature
                self.add_auto_segment(
                    il_start_vaddr, body.code_size, file_offset + header_size, body.code_size,
                    int(SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable),
                )
                self.add_user_section(
                    f".cil.{row_index + 1}", il_start_vaddr, body.code_size,
                    SectionSemantics.ReadOnlyCodeSectionSemantics,
                )

                # Publish all view-local method state and executable backing
                # before asking core analysis to construct the function.
                # Otherwise analysis can infer a native-width prototype while
                # the loader is still incomplete and discard the CLR type.
                function_type = self._bn_function_type(signature)
                self._safe_define_symbol(
                    SymbolType.FunctionSymbol, il_start_vaddr, sym_name
                )
                func = self.add_function(
                    il_start_vaddr,
                    self.platform,
                    func_type=function_type,
                )
                if func and function_type:
                    func.set_user_type(function_type)
                parsed += 1
            except (MethodBodyError, AttributeError, IndexError, TypeError, ValueError) as e:
                log_warn(f"[dotninja] Error parsing method index {row_index}: {e}")

        if candidates and not parsed:
            raise ValueError("no managed method body ownership could be established")

        # Map MemberRef (0x0AXXXXXX) tokens for external/framework methods
        member_ref = getattr(mdtables, "MemberRef", None) if mdtables else None
        if member_ref:
            extern_base = 0x50001000
            for row_index, _ in enumerate(member_ref):
                try:
                    token = 0x0A000000 | (row_index + 1)
                    target_vaddr = external_slot_address(
                        extern_base, row_index, self.arch.address_size
                    )
                    target = self.metadata_resolver.resolve_target(token)

                    if target:
                        sym_name = str(target.name)
                        sym_type = SymbolType.ImportedFunctionSymbol
                    else:
                        sym_name = f"extern_0x{token:08x}"
                        sym_type = SymbolType.ExternalSymbol

                    if target and target.kind == "method":
                        self._safe_define_symbol(sym_type, target_vaddr, sym_name)
                        self._materialize_external(
                            target_vaddr, sym_name, target.signature
                        )
                        mapped = TokenTarget(token, "method", target_vaddr, sym_name, target.signature)
                        self.metadata_resolver.register_target(mapped)
                        self.session_data["token_map"][token] = target_vaddr
                        self.session_data["token_targets"][token] = mapped
                    elif target:
                        field_type = getattr(target.signature, "field_type", None)
                        if field_type is not None:
                            self.define_data_var(target_vaddr, self._bn_type(field_type))
                            self._safe_define_symbol(
                                SymbolType.ExternalSymbol, target_vaddr, sym_name
                            )
                        self.session_data["token_targets"][token] = target
                except Exception as e:
                    log_warn(f"[dotninja] Error mapping MemberRef row {row_index}: {e}")

    def _enrich_instructions(self):
        from .arch import decode_instruction
        for start, body in self.session_data.get("method_bodies", {}).items():
            try:
                curr_addr = int(start)
                highest = curr_addr + int(body.code_size)
                while curr_addr < highest:
                    data = self.read(curr_addr, self.arch.max_instr_length)
                    if not data:
                        break

                    opcode, operand, length = decode_instruction(data, curr_addr)
                    if not opcode or length == 0:
                        curr_addr += 1
                        continue

                    if (
                        operand is not None
                        and isinstance(operand, int)
                        and (operand >> 24) in (0x70, 0x06, 0x0A, 0x01, 0x02, 0x04)
                    ):
                        resolved = self.metadata_resolver.resolve_token(operand)
                        if resolved:
                            self.set_comment_at(curr_addr, str(resolved))

                    curr_addr += int(length)
            except Exception as e:
                log_warn(f"[dotninja] Error enriching method at {start:#x}: {e}")

    def _reconstruct_types(self):
        """Register named structures and separate static fields from instance layout."""
        from binaryninja import StructureBuilder, Type
        tables = self.metadata_resolver.tables
        field_offsets = {}
        for layout in getattr(tables, "FieldLayout", None) or ():
            field = getattr(layout, "Field", None)
            row_index = int(getattr(field, "row_index", 0) or 0)
            if row_index:
                field_offsets[row_index] = int(getattr(layout, "Offset", 0) or 0)
        class_layouts = {}
        for layout in getattr(tables, "ClassLayout", None) or ():
            parent = getattr(layout, "Parent", None)
            row_index = int(getattr(parent, "row_index", 0) or 0)
            if row_index:
                class_layouts[row_index] = layout
        for type_index, row in enumerate(getattr(tables, "TypeDef", None) or (), 1):
            name = self.metadata_resolver._qualified_type(row)
            if not name or name == "<Module>":
                continue
            builder = StructureBuilder.create()
            layout = class_layouts.get(type_index)
            if layout:
                packing = int(getattr(layout, "PackingSize", 0) or 0)
                class_size = int(getattr(layout, "ClassSize", 0) or 0)
                builder.packed = bool(packing == 1)
                if packing:
                    builder.alignment = packing
                if class_size:
                    builder.width = class_size
            static_fields = []
            for field_index_ref in getattr(row, "FieldList", ()) or ():
                field = getattr(field_index_ref, "row", field_index_ref)
                flags_obj = getattr(field, "Flags", 0)
                try:
                    is_static = bool(getattr(flags_obj, "fdStatic", False) or (int(flags_obj) & 0x10))
                except (TypeError, ValueError):
                    is_static = bool(getattr(flags_obj, "fdStatic", False))
                field_name = str(getattr(field, "Name", "field"))
                signature = self.metadata_resolver.field_signature(field)
                if is_static:
                    static_fields.append(field_name)
                    continue
                width = 1
                if signature:
                    from .signatures import native_width
                    width = native_width(signature.field_type, self.arch.address_size)
                field_type = Type.int(width, False)
                field_index = int(getattr(field, "row_index", 0) or 0)
                if field_index in field_offsets:
                    builder.insert(field_offsets[field_index], field_type, field_name)
                else:
                    builder.append(field_type, field_name)
            self.define_user_type(name, Type.structure_type(builder))
            if static_fields:
                self.session_data.setdefault("static_fields", {})[name] = static_fields

    def _map_entry_point(self):
        try:
            ep_token = int(self.pe.net.struct.EntryPointTokenOrRva)
            if ep_token == 0:
                return
            if (ep_token >> 24) == 0x06 and ep_token in self.session_data["token_map"]:
                self.add_entry_point(int(self.session_data["token_map"][ep_token]))
            else:
                self.add_entry_point(int(self._image_base + ep_token))
        except Exception as e:
            log_warn(f"[dotninja] Could not set entry point: {e}")

    def perform_get_address_size(self):
        return 8 if self.pe and getattr(self.pe, "PE_TYPE", None) == 0x20B else 4
