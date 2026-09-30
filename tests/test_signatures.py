import pytest
import dnfile
from pathlib import Path
from signatures import ElementType, FieldSignature, SignatureError, parse_local_signature, parse_member_signature, parse_method_signature, stack_effect

def test_instance_method_signature_and_stack_effect():
    signature = parse_method_signature(bytes([0x20, 0x02, 0x08, 0x08, 0x0E]))
    assert signature.has_this
    assert signature.return_type.element == ElementType.I4
    assert [x.element for x in signature.parameters] == [ElementType.I4, ElementType.STRING]
    assert stack_effect(signature, "callvirt") == (3, 1)
    assert stack_effect(signature, "newobj") == (2, 1)

def test_field_and_local_signatures_are_distinct():
    assert isinstance(parse_member_signature(bytes([0x06, 0x08])), FieldSignature)
    assert [x.element for x in parse_local_signature(bytes([0x07, 0x02, 0x08, 0x1D, 0x05])).locals] == [ElementType.I4, ElementType.SZARRAY]

def test_truncated_signature_rejected():
    with pytest.raises(SignatureError):
        parse_method_signature(bytes([0x00, 0x01]))

def test_dnfile_heap_item_value_bytes_are_accepted():
    class HeapItem:
        value = None
        def value_bytes(self):
            return bytes([0x06, 0x08])
    from dotninja.metadata import _blob_bytes
    assert _blob_bytes(HeapItem()) == bytes([0x06, 0x08])

def test_fixture_member_refs_have_qualified_declaring_types():
    from dotninja.metadata import MetadataResolver

    fixture = Path(__file__).parents[1] / "fixtures" / "fixture-pe64.exe"
    resolver = MetadataResolver(dnfile.dnPE(str(fixture)))
    constructor = resolver.resolve_target(0x0A000001)
    write_line = resolver.resolve_target(0x0A00000F)
    assert constructor is not None
    assert constructor.name == "System.Runtime.CompilerServices.CompilationRelaxationsAttribute::.ctor"
    assert write_line is not None
    assert write_line.name == "System.Console::WriteLine"
