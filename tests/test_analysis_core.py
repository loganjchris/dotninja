import pytest
from analysis_core import EmulationError, StackMergeError, StackValue, emulate_pure_cil, merge_stack_states
from dotninja.lifter import array_element_size, call_argument_indices, get_stack_delta

def test_stack_merge_reconciles_unknown_and_rejects_depth():
    assert merge_stack_states((StackValue(),), (StackValue("i4", 4),)) == (StackValue("i4", 4),)
    with pytest.raises(StackMergeError):
        merge_stack_states((), (StackValue(),))

def test_bounded_emulator_handles_array_decryptor_shape():
    program = [("ldc.i4", 2), ("newarr",), ("stloc", 0), ("ldloc", 0), ("ldc.i4", 0), ("ldc.i4", 65), ("stelem",), ("ldstr", "ok"), ("ret",)]
    assert emulate_pure_cil(program) == "ok"

def test_emulator_rejects_unknown_code():
    with pytest.raises(EmulationError):
        emulate_pure_cil([("call", 1)])

def test_fixture_stack_effect_boundaries():
    assert get_stack_delta("beq.s") == -2
    assert get_stack_delta("stsfld") == -1
    assert get_stack_delta("newarr") == 0

def test_call_arguments_are_taken_from_evaluation_stack_in_declaration_order():
    assert call_argument_indices(height=4, pops=3) == (1, 2, 3)
    assert call_argument_indices(height=4, pops=3, indirect=True) == (1, 2)

def test_array_element_widths_follow_typed_opcodes():
    assert array_element_size("stelem.i2", 8) == 2
    assert array_element_size("ldelem.u1", 8) == 1
    assert array_element_size("ldelem.i4", 8) == 4
    assert array_element_size("ldelema", 8) == 8
