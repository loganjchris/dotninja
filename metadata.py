"""
dotninja.metadata
Phase 5: Metadata Enrichment & Type Reconstruction
"""

from binaryninja.log import log_error


class MetadataResolver:
    def __init__(self, pe):
        self.pe = pe
        self._build_class_map()

    def _build_class_map(self):
        """Pre-compute a mapping of MethodDef indices to their parent TypeDef (Class/Namespace)"""
        self.method_to_class = {}
        mdtables = (
            getattr(self.pe.net, "mdtables", None)
            if hasattr(self.pe, "net") and self.pe.net
            else None
        )
        type_def = getattr(mdtables, "TypeDef", None) if mdtables else None
        if not type_def:
            return

        for type_row in type_def:
            # dnfile helpfully resolves MethodList into an actual list of MethodDef rows
            if hasattr(type_row, "MethodList") and isinstance(
                type_row.MethodList, list
            ):
                for method_row in type_row.MethodList:
                    if hasattr(method_row, "row_index"):
                        # dnfile's row_index is 1-based. We use 0-based indexing internally.
                        self.method_to_class[method_row.row_index - 1] = type_row

    def get_method_full_name(self, method_row_idx):
        """Reconstructs 'Namespace.Class::MethodName'"""
        mdtables = (
            getattr(self.pe.net, "mdtables", None)
            if hasattr(self.pe, "net") and self.pe.net
            else None
        )
        method_def = getattr(mdtables, "MethodDef", None) if mdtables else None
        if not method_def or not (0 <= method_row_idx < len(method_def)):
            return f"method_0x{method_row_idx+1:x}"

        row = method_def[method_row_idx]
        name = getattr(row, "Name", None) or f"method_0x{method_row_idx+1:x}"

        parent_class = self.method_to_class.get(method_row_idx)
        if parent_class:
            class_name = getattr(parent_class, "TypeName", "")
            namespace = getattr(parent_class, "TypeNamespace", "")
            if namespace:
                return f"{namespace}.{class_name}::{name}"
            return f"{class_name}::{name}"
        return name

    def resolve_token(self, token):
        """Resolves a 32-bit metadata token to its plaintext string representation"""
        table_idx = token >> 24
        row_idx = (token & 0x00FFFFFF) - 1

        if table_idx == 0x70:  # UserString (#US stream)
            try:
                # The token's lower 3 bytes act as an offset into the string heap
                offset = token & 0x00FFFFFF
                string_val = self.pe.net.user_strings.get(offset)
                print(
                    f"Metadata parsing {string_val} with {offest}. {table_idx} {row_idx}"
                )
                if string_val:
                    # Decode HeapItemString (bytes-like) to Python string
                    try:
                        decoded = string_val.decode("utf-8")
                    except Exception as e:
                        decoded = str(string_val)
                        print(f"string issue as {e}")
                    return f'"{decoded}"'
                else:
                    return ""  # Empty string if not found
            except Exception as e:
                log_error(f"Error reading string: {e}")
            return '"<string read error>"'

        mdtables = (
            getattr(self.pe.net, "mdtables", None)
            if hasattr(self.pe, "net") and self.pe.net
            else None
        )
        if not mdtables:
            return None

        try:
            if table_idx == 0x06:  # MethodDef
                return self.get_method_full_name(row_idx)

            elif table_idx == 0x0A:  # MemberRef (External method or field)
                table = getattr(mdtables, "MemberRef", None)
                if table and 0 <= row_idx < len(table):
                    row = table[row_idx]
                    class_token = getattr(row, "Class", None)
                    class_name = ""
                    if class_token:
                        class_table_idx = getattr(class_token, "table_index", None)
                        class_row_idx = getattr(class_token, "row_index", 0) - 1
                        if class_table_idx == 0x01:  # TypeRef
                            tr_table = getattr(mdtables, "TypeRef", None)
                            if tr_table and 0 <= class_row_idx < len(tr_table):
                                tr_row = tr_table[class_row_idx]
                                ns = tr_row.TypeNamespace
                                class_name = (
                                    f"{ns}.{tr_row.TypeName}" if ns else tr_row.TypeName
                                )
                        elif class_table_idx == 0x02:  # TypeDef
                            td_table = getattr(mdtables, "TypeDef", None)
                            if td_table and 0 <= class_row_idx < len(td_table):
                                td_row = td_table[class_row_idx]
                                ns = td_row.TypeNamespace
                                class_name = (
                                    f"{ns}.{td_row.TypeName}" if ns else td_row.TypeName
                                )
                    method_name = getattr(row, "Name", f"member_0x{row_idx+1:x}")
                    return f"{class_name}::{method_name}" if class_name else method_name

            elif table_idx == 0x01:  # TypeRef
                table = getattr(mdtables, "TypeRef", None)
                if table and 0 <= row_idx < len(table):
                    row = table[row_idx]
                    return (
                        f"{row.TypeNamespace}.{row.TypeName}"
                        if row.TypeNamespace
                        else row.TypeName
                    )

            elif table_idx == 0x02:  # TypeDef
                table = getattr(mdtables, "TypeDef", None)
                if table and 0 <= row_idx < len(table):
                    row = table[row_idx]
                    return f"{row.TypeName}"

            elif table_idx == 0x04:  # FieldDef
                table = getattr(mdtables, "Field", None)
                if table and 0 <= row_idx < len(table):
                    row = table[row_idx]
                    return f"{row.Name} (Field)"
        except Exception as e:
            log_error(f"Error resolving token: {e}")
            return f"<invalid token {hex(token)}>"

        return None
