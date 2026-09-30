"""
dotninja.view
Phase 2 & 5: Fault-Tolerant .NET BinaryView (CLR)
Includes strict type sanitization and per-phase exception isolation.
"""

import dnfile
from binaryninja import (
    Architecture,
    BinaryView,
    SectionSemantics,
    SegmentFlag,
    Symbol,
    SymbolType,
)
from binaryninja.log import log_error, log_info, log_warn

from .metadata import MetadataResolver


class DotNetView(BinaryView):
    name = "DotNet"
    long_name = ".NET Managed Executable (CLR)"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.arch = Architecture["dotnet"]
        self.platform = self.arch.standalone_platform
        self.pe = None
        self.metadata_resolver = None
        self._image_base = 0x400000

    @classmethod
    def is_valid_for_data(cls, data):
        if data.view_type != "Raw":
            return False

        try:
            raw_bytes = data.read(0, data.length)
            pe = dnfile.dnPE(data=raw_bytes)
            if (
                hasattr(pe, "net")
                and pe.net is not None
                and hasattr(pe.net, "mdtables")
                and pe.net.mdtables is not None
            ):
                return True
        except Exception as e:
            log_error(f"[dotninja] Validation failed: {e}")

        return False

    def init(self):
        try:
            raw_bytes = self.parent_view.read(0, self.parent_view.length)
            self.pe = dnfile.dnPE(data=raw_bytes)
            self.metadata_resolver = MetadataResolver(self.pe)

            self.session_data["token_map"] = {}
            from .arch import DotNetArch

            DotNetArch.token_map = self.session_data["token_map"]

            if hasattr(self.pe, "OPTIONAL_HEADER") and hasattr(
                self.pe.OPTIONAL_HEADER, "ImageBase"
            ):
                self._image_base = int(self.pe.OPTIONAL_HEADER.ImageBase)

            # Isolated initialization phases to ensure view opens even if a non-critical phase fails
            for phase_name, phase_func in [
                ("Sections Mapping", lambda: self._map_sections(raw_bytes)),
                ("P/Invoke Mapping", self._map_pinvokes),
                ("Method Parsing", lambda: self._parse_methods(raw_bytes)),
                ("Entry Point Mapping", self._map_entry_point),
                ("Instruction Enrichment", self._enrich_instructions),
            ]:
                try:
                    phase_func()
                except Exception as phase_err:
                    log_warn(
                        f"[dotninja] Non-fatal exception during {phase_name}: {phase_err}"
                    )

            log_info(
                f"[dotninja] DotNetView initialized successfully for {self.file.filename}"
            )
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
        except Exception as e:
            log_warn(
                f"[dotninja] Could not define symbol '{name}' at {hex(int(addr))}: {e}"
            )

    def _map_sections(self, raw_bytes):
        base_addr = int(self._image_base)
        self.add_auto_segment(
            base_addr, 0x1000, 0, 0x1000, int(SegmentFlag.SegmentReadable)
        )

        for section in self.pe.sections:
            vaddr = int(base_addr + section.VirtualAddress)
            vsize = int(section.Misc_VirtualSize)
            raw_size = int(section.SizeOfRawData)
            raw_ptr = int(section.PointerToRawData)

            flags = int(SegmentFlag.SegmentReadable)
            if section.Characteristics & 0x20000000:
                flags |= int(SegmentFlag.SegmentExecutable)
            if section.Characteristics & 0x80000000:
                flags |= int(SegmentFlag.SegmentWritable)

            self.add_auto_segment(vaddr, vsize, raw_ptr, raw_size, flags)

            sec_name = str(section.Name.decode("utf-8", errors="ignore").strip("\x00"))
            self.add_user_section(
                sec_name, vaddr, vsize, SectionSemantics.ReadOnlyCodeSectionSemantics
            )

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

        self.add_auto_segment(
            extern_base,
            0x1000,
            0,
            0,
            int(SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable),
        )
        self.add_user_section(
            ".extern", extern_base, 0x1000, SectionSemantics.ExternalSectionSemantics
        )

        offset = 0
        for impl_row in impl_map:
            try:
                method_idx = int(impl_row.MemberForwarded.row_index) - 1
                if 0 <= method_idx < len(method_def):
                    mod_idx = int(impl_row.ImportScope.row_index) - 1
                    if 0 <= mod_idx < len(module_ref):
                        dll_name = str(module_ref[mod_idx].Name)
                        import_name = str(impl_row.ImportName)

                        target_vaddr = int(extern_base + offset)
                        sym_name = f"{dll_name}!{import_name}"

                        func = self.add_function(target_vaddr, self.platform)
                        if func:
                            self._safe_define_symbol(
                                SymbolType.ImportedFunctionSymbol,
                                target_vaddr,
                                sym_name,
                            )

                        token = 0x06000000 | (method_idx + 1)
                        self.session_data["token_map"][token] = target_vaddr

                        offset += 4
            except Exception as e:
                log_warn(f"[dotninja] Skipping P/Invoke import entry due to error: {e}")

    def _parse_methods(self, raw_bytes):
        mdtables = (
            getattr(self.pe.net, "mdtables", None)
            if hasattr(self.pe, "net") and self.pe.net
            else None
        )
        method_def = getattr(mdtables, "MethodDef", None) if mdtables else None
        if not method_def:
            return

        for row_index, method_row in enumerate(method_def):
            try:
                rva = int(method_row.Rva)
                if rva == 0:
                    continue

                file_offset = self.pe.get_offset_from_rva(rva)
                if file_offset is None or file_offset >= len(raw_bytes):
                    continue

                header_byte = raw_bytes[file_offset]
                is_fat = (header_byte & 0x03) == 0x03

                if is_fat:
                    if file_offset + 2 > len(raw_bytes):
                        continue
                    flags_and_size = int.from_bytes(
                        raw_bytes[file_offset : file_offset + 2], "little"
                    )
                    header_size = (flags_and_size >> 12) * 4
                else:
                    header_size = 1

                il_start_vaddr = int(self._image_base + rva + header_size)
                sym_name = str(self.metadata_resolver.get_method_full_name(row_index))

                func = self.add_function(il_start_vaddr, self.platform)
                if func:
                    self._safe_define_symbol(
                        SymbolType.FunctionSymbol, il_start_vaddr, sym_name
                    )

                token = 0x06000000 | (row_index + 1)
                self.session_data["token_map"][token] = il_start_vaddr
            except Exception as e:
                log_warn(f"[dotninja] Error parsing method index {row_index}: {e}")

        # Map MemberRef (0x0AXXXXXX) tokens for external/framework methods
        member_ref = getattr(mdtables, "MemberRef", None) if mdtables else None
        if member_ref:
            extern_base = 0x50001000
            for row_index, _ in enumerate(member_ref):
                try:
                    token = 0x0A000000 | (row_index + 1)
                    target_vaddr = int(extern_base + (row_index * 4))
                    resolved = self.metadata_resolver.resolve_token(token)

                    if resolved:
                        sym_name = str(resolved)
                        sym_type = SymbolType.ImportedFunctionSymbol
                    else:
                        sym_name = f"extern_0x{token:08x}"
                        sym_type = SymbolType.ExternalSymbol

                    func = self.add_function(target_vaddr, self.platform)
                    if func:
                        self._safe_define_symbol(sym_type, target_vaddr, sym_name)

                    self.session_data["token_map"][token] = target_vaddr
                except Exception as e:
                    log_warn(f"[dotninja] Error mapping MemberRef row {row_index}: {e}")

    def _enrich_instructions(self):
        for func in self.functions:
            try:
                curr_addr = int(func.start)
                highest = int(func.highest_address)
                while curr_addr < highest:
                    data = self.read(curr_addr, self.arch.max_instr_length)
                    if not data:
                        break

                    opcode, operand, length = self.arch._decode_instruction(
                        data, curr_addr
                    )
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
                log_warn(f"[dotninja] Error enriching instructions in {func.name}: {e}")

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
