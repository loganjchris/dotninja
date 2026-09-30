"""
dotninja.lifter
Phase 4 & 5: Pre-Pass Stack Simulation & LLIL Lifter (Fully Audited & Stabilized)
"""

from collections import deque
from binaryninja import LLIL_TEMP
from binaryninja.log import log_warn
from .signatures import MethodSignature, native_width, stack_effect
from .arch import decode_instruction


def _eval(index):
    return LLIL_TEMP(max(0, int(index)))


def _local(index):
    return LLIL_TEMP(0x100000 + max(0, int(index)))


def _argument(index):
    return LLIL_TEMP(0x200000 + max(0, int(index)))


def call_argument_indices(height, pops, indirect=False):
    """Evaluation-stack slots containing call arguments, in declaration order."""
    argument_count = max(0, int(pops) - (1 if indirect else 0))
    first = max(0, int(height) - int(pops))
    return tuple(range(first, first + argument_count))


def array_element_size(opcode_name, pointer_size):
    """Storage width for typed CIL array element instructions."""
    name = opcode_name.lower()
    suffix = name.rsplit(".", 1)[-1] if "." in name else ""
    if suffix in ("i1", "u1"):
        return 1
    if suffix in ("i2", "u2"):
        return 2
    if suffix in ("i4", "u4", "r4"):
        return 4
    if suffix in ("i8", "r8"):
        return 8
    return int(pointer_size)


def _method_context(view, address):
    for start, body in view.session_data.get("method_bodies", {}).items():
        if int(start) <= int(address) < int(start) + int(body.code_size):
            return int(start), body
    return None, None


def _leave_destination(view, address, direct_target):
    """Route leave through an enclosing finally handler when required."""
    start, body = _method_context(view, address)
    if start is None or body is None:
        return direct_target
    relative = int(address) - start
    candidates = [
        region for region in body.exception_regions
        if region.flags & 0x2
        and region.try_offset <= relative < region.try_offset + region.try_length
    ]
    if not candidates:
        return direct_target
    region = min(candidates, key=lambda item: item.try_length)
    return start + int(region.handler_offset)


def _finally_destination(view, address):
    """Resolve a finally handler's continuation when all leaves agree."""
    start, body = _method_context(view, address)
    if start is None or body is None:
        return None
    relative = int(address) - start
    region = next((
        item for item in body.exception_regions
        if item.flags & 0x2
        and item.handler_offset <= relative < item.handler_offset + item.handler_length
    ), None)
    if region is None:
        return None
    cursor = start + int(region.try_offset)
    end = cursor + int(region.try_length)
    targets = set()
    while cursor < end:
        data = view.read(cursor, 16)
        if not data:
            break
        try:
            opcode, operand, length = decode_instruction(data, cursor)
        except Exception:
            break
        if not opcode or length <= 0:
            break
        if opcode.name.lower() in ("leave", "leave.s") and operand is not None:
            targets.add(cursor + length + int(operand))
        cursor += length
    return next(iter(targets)) if len(targets) == 1 else None


def get_stack_delta(opcode_name, operand_val=None):
    """
    Robust stack delta calculation accounting for instruction type and popped arguments.
    """
    name = opcode_name.lower()

    if name in (
        "nop",
        "break",
        "volatile.",
        "readonly.",
        "tail.",
        "unaligned.",
        "no.",
        "constrained.",
        "prefix1",
        "prefix2",
        "prefix3",
        "prefix4",
        "prefix5",
        "prefix6",
        "prefix7",
        "prefixref",
    ):
        return 0

    if name.startswith("ldc.") or name in (
        "ldstr",
        "ldnull",
        "ldftn",
        "ldsflda",
        "ldtoken",
        "ldvirtftn",
        "localloc",
        "sizeof",
        "arglist",
        "ldsfld",
    ):
        return 1

    if name.startswith("ldloc") or name.startswith("ldarg"):
        return 1

    if name.startswith("ldind.") or name.startswith("conv.") or name in (
        "ldfld",
        "ldflda",
        "ldlen",
        "box",
        "unbox",
        "unbox.any",
        "isinst",
        "castclass",
        "ckfinite",
        "newarr",
    ):
        return 0  # Pops object/ptr/val, pushes converted/field/ptr/val

    if name.startswith("ldelem") or name in ("ldelema",):
        return -1  # Pops array and index, pushes element

    if name == "dup":
        return 1

    if name.startswith("stloc") or name.startswith("starg") or name in ("pop", "stsfld"):
        return -1

    if name.startswith("stind.") or name in ("stfld", "stobj", "initobj"):
        return -2  # Pops target and value

    if name.startswith("stelem.") or name in ("stelem", "cpblk", "initblk"):
        return -3  # Pops array/target, index/value, and value/length

    if name in (
        "brtrue",
        "brtrue.s",
        "brfalse",
        "brfalse.s",
        "jmp",
        "switch",
        "throw",
    ):
        return -1

    if name in ("rethrow", "endfinally", "endfilter", "br", "br.s", "leave", "leave.s", "ret"):
        return 0

    if name in (
        "beq", "beq.s", "bge", "bge.s", "bge.un", "bge.un.s",
        "bgt", "bgt.s", "bgt.un", "bgt.un.s", "ble", "ble.s",
        "ble.un", "ble.un.s", "blt", "blt.s", "blt.un", "blt.un.s",
        "bne.un", "bne.un.s",
    ):
        return -2

    if name in (
        "beq",
        "beq.s",
        "bge",
        "bge.s",
        "bge.un",
        "bge.un.s",
        "bgt",
        "bgt.s",
        "bgt.un",
        "bgt.un.s",
        "ble",
        "ble.s",
        "ble.un",
        "ble.un.s",
        "blt",
        "blt.s",
        "blt.un",
        "blt.un.s",
        "bne.un",
        "bne.un.s",
        "ceq",
        "cgt",
        "cgt.un",
        "clt",
        "clt.un",
        "add",
        "add.ovf",
        "add.ovf.un",
        "sub",
        "sub.ovf",
        "sub.ovf.un",
        "mul",
        "mul.ovf",
        "mul.ovf.un",
        "div",
        "div.un",
        "rem",
        "rem.un",
        "and",
        "or",
        "xor",
        "shl",
        "shr",
        "shr.un",
    ):
        return -1

    if name in ("newobj", "call", "callvirt", "calli", "jmp"):
        raise ValueError(f"{name} requires a parsed signature")

    raise ValueError(f"unclassified CIL opcode: {name}")


def analyze_function_stack(arch, func):
    """
    Breadth-First Search (BFS) Pre-Pass Analyzer with explicit guardrails against
    unresolved targets, out-of-bounds reads, and invalid branch offsets.
    """
    if not func:
        return {}

    if "cil_stack" in func.session_data:
        return func.session_data["cil_stack"]

    stack_state = {func.start: 0}
    queue = deque([func.start])
    view = func.view
    conflicts = []

    body = view.session_data.get("method_bodies", {}).get(func.start)
    if body is not None:
        for region in body.exception_regions:
            handler = func.start + int(region.handler_offset)
            handler_height = 0 if region.flags & 0x2 else 1
            stack_state.setdefault(handler, handler_height)
            queue.append(handler)

    while queue:
        curr_addr = queue.popleft()

        if curr_addr is None:
            continue
        current_height = stack_state.get(curr_addr, 0)

        data = view.read(curr_addr, arch.max_instr_length)
        if not data:
            continue

        try:
            opcode, operand, length = decode_instruction(data, curr_addr)
        except Exception as exc:
            log_warn(f"[dotninja] Decode failed at {curr_addr:#x}: {exc}")
            continue

        if not opcode or length == 0:
            continue

        try:
            if opcode.name.lower() in ("call", "callvirt", "calli", "newobj", "jmp"):
                target = view.session_data.get("token_targets", {}).get(operand)
                signature = getattr(target, "signature", None)
                if not isinstance(signature, MethodSignature):
                    raise ValueError("missing parsed call signature")
                pops, pushes = stack_effect(signature, opcode.name.lower())
                delta = pushes - pops
            else:
                delta = get_stack_delta(opcode.name, operand)
        except ValueError as exc:
            log_warn(f"[dotninja] Stack classification failed at {curr_addr:#x}: {exc}")
            delta = 0
        next_height = max(0, current_height + delta)

        try:
            info = arch.get_instruction_info(data, curr_addr)
        except Exception as exc:
            log_warn(f"[dotninja] Branch decode failed at {curr_addr:#x}: {exc}")
            info = None

        special_targets = None
        opcode_name = opcode.name.lower()
        if opcode_name in ("leave", "leave.s") and operand is not None:
            direct = curr_addr + length + int(operand)
            special_targets = (_leave_destination(view, curr_addr, direct),)
            next_height = 0
        elif opcode_name == "endfinally":
            continuation = _finally_destination(view, curr_addr)
            special_targets = (continuation,) if continuation is not None else ()

        if special_targets is not None:
            branches = special_targets
        elif info and info.branches:
            branches = tuple(branch.target for branch in info.branches)
        else:
            branches = ()
        if branches:
            for target in branches:
                if target is not None:
                    previous = stack_state.get(target)
                    if previous is None:
                        stack_state[target] = next_height
                        queue.append(target)
                    elif previous != next_height:
                        conflicts.append((target, previous, next_height))

        # Propagate to standard fallthrough if not an exit instruction
        if opcode.name.lower() not in (
            "br",
            "br.s",
            "leave",
            "leave.s",
            "ret",
            "throw",
            "rethrow",
            "endfinally",
            "endfilter",
            "jmp",
        ):
            next_addr = curr_addr + length
            if next_addr not in stack_state:
                stack_state[next_addr] = next_height
                queue.append(next_addr)

    if conflicts:
        func.session_data["cil_stack_conflicts"] = conflicts
        for target, left, right in conflicts:
            log_warn(f"[dotninja] Stack-depth conflict at {target:#x}: {left} != {right}")

    func.session_data["cil_stack"] = stack_state
    return stack_state


def lift_instruction(arch, data, addr, il):
    """
    Audited instruction lifter translating CIL stack operations into BNIL register expressions.
    """
    try:
        opcode, operand, length = decode_instruction(data, addr)
    except Exception:
        il.append(il.unimplemented())
        return 1

    if not opcode:
        il.append(il.unimplemented())
        return 1

    height = 0
    token_map = {}
    if il.source_function:
        stack_state = analyze_function_stack(arch, il.source_function)
        height = stack_state.get(addr, 0)
        token_map = il.source_function.view.session_data.get("token_map", {})

    name = opcode.name.lower()

    # -------------------------------------------------------------
    # Helper to resolve relative instruction offsets vs absolute RVAs
    # -------------------------------------------------------------
    def _resolve_target(op_val, is_relative=True):
        if op_val is None:
            return addr + length
        if is_relative and abs(op_val) < 0x100000:
            return addr + length + op_val
        # If absolute virtual address or large RVA
        if op_val >= 0x400000:
            return op_val
        return addr + length + op_val

    # Helper for conditional branch emission ensuring valid instruction handles
    def _emit_branch_if(true_target, false_target, invert=False, cond_expr=None):
        if cond_expr is None:
            src_reg = _eval(height - 1)
            reg_expr = il.reg(4, src_reg)
            const_zero = il.const(4, 0)
            if invert:
                cond_expr = il.compare_equal(4, reg_expr, const_zero)
            else:
                cond_expr = il.compare_not_equal(4, reg_expr, const_zero)

        import binaryninja

        t_label = binaryninja.LowLevelILLabel()
        f_label = binaryninja.LowLevelILLabel()

        il.append(il.if_expr(cond_expr, t_label, f_label))
        il.mark_label(t_label)
        il.append(il.jump(il.const_pointer(arch.address_size, true_target)))
        il.mark_label(f_label)
        il.append(il.jump(il.const_pointer(arch.address_size, false_target)))

    # -------------------------------------------------------------
    # CIL Opcode Lifting Logic
    # -------------------------------------------------------------

    # Prefixes / Hints / Nops
    if name in (
        "nop",
        "break",
        "volatile.",
        "readonly.",
        "tail.",
        "unaligned.",
        "no.",
        "constrained.",
        "prefix1",
        "prefix2",
        "prefix3",
        "prefix4",
        "prefix5",
        "prefix6",
        "prefix7",
        "prefixref",
    ):
        il.append(il.nop())

    # Constants & Literals
    elif name.startswith("ldc.i4"):
        val = operand if operand is not None else 0
        if name.endswith(".m1"):
            val = -1
        elif name[-1].isdigit():
            val = int(name[-1])
        il.append(il.set_reg(4, _eval(height), il.const(4, val)))

    elif name == "ldc.i8":
        val = operand if operand is not None else 0
        il.append(il.set_reg(8, _eval(height), il.const(8, int(val))))

    elif name in ("ldc.r4", "ldc.r8"):
        val = float(operand if operand is not None else 0.0)
        expression = il.float_const_single(val) if name == "ldc.r4" else il.float_const_double(val)
        il.append(il.set_reg(4 if name == "ldc.r4" else 8, _eval(height), expression))

    elif name in ("ldstr", "ldnull", "ldftn", "ldsflda", "ldtoken", "ldvirtftn"):
        val = operand if operand is not None else 0
        if name in ("ldstr", "ldftn"):
            val = token_map.get(operand, val)
        il.append(il.set_reg(arch.address_size, _eval(height), il.const_pointer(arch.address_size, val)))

    elif name in ("sizeof", "arglist", "localloc"):
        val = operand if operand is not None else 0
        il.append(il.set_reg(4, _eval(height), il.const(4, val)))

    # Variable Access
    elif name.startswith("ldloc") or name.startswith("ldarg"):
        val = (
            int(operand)
            if isinstance(operand, int)
            else (int(name[-1]) if name[-1].isdigit() else 0)
        )
        if name.startswith("ldarg"):
            # CIL arguments are modeled as stack parameters. Reading them from
            # the incoming stack gives Binary Ninja a real parameter location
            # instead of an uninitialized LLIL temporary.
            address = il.add(
                arch.address_size,
                il.reg(arch.address_size, "sp"),
                il.const(arch.address_size, (val + 1) * arch.address_size),
            )
            source_expr = il.load(arch.address_size, address)
        else:
            source_expr = il.reg(arch.address_size, _local(val))
        il.append(il.set_reg(arch.address_size, _eval(height), source_expr))

    elif name.startswith("stloc") or name.startswith("starg"):
        val = (
            operand
            if operand is not None
            else (int(name[-1]) if name[-1].isdigit() else 0)
        )
        var_name = "arg" if name.startswith("starg") else "loc"
        src_reg = _eval(height - 1)
        destination = _argument(val) if var_name == "arg" else _local(val)
        il.append(il.set_reg(arch.address_size, destination, il.reg(arch.address_size, src_reg)))

    # Stack Management
    elif name == "pop":
        il.append(il.nop())

    elif name == "dup":
        src_reg = _eval(height - 1)
        il.append(il.set_reg(arch.address_size, _eval(height), il.reg(arch.address_size, src_reg)))

    # Field & Object Access
    elif name in (
        "ldsfld",
        "ldfld",
        "ldflda",
        "isinst",
        "castclass",
        "box",
        "unbox",
        "unbox.any",
    ):
        val = operand if operand is not None else 0
        il.append(il.set_reg(arch.address_size, _eval(height), il.const_pointer(arch.address_size, val)))

    elif name in ("stsfld", "stfld", "stobj", "initobj"):
        il.append(il.nop())

    # Arithmetic & Logic Operations
    elif name in (
        "add",
        "add.ovf",
        "add.ovf.un",
        "sub",
        "sub.ovf",
        "sub.ovf.un",
        "mul",
        "mul.ovf",
        "mul.ovf.un",
        "div",
        "div.un",
        "rem",
        "rem.un",
        "and",
        "or",
        "xor",
        "shl",
        "shr",
        "shr.un",
    ):
        left_reg = _eval(height - 2)
        right_reg = _eval(height - 1)
        left = il.reg(4, left_reg)
        right = il.reg(4, right_reg)

        if name.startswith("add"):
            res = il.add(4, left, right)
        elif name.startswith("sub"):
            res = il.sub(4, left, right)
        elif name.startswith("mul"):
            res = il.mult(4, left, right)
        elif name in ("div", "div.un"):
            res = (
                il.div_unsigned(4, left, right)
                if name == "div.un"
                else il.div_signed(4, left, right)
            )
        elif name in ("rem", "rem.un"):
            res = (
                il.mod_unsigned(4, left, right)
                if name == "rem.un"
                else il.mod_signed(4, left, right)
            )
        elif name == "and":
            res = il.and_expr(4, left, right)
        elif name == "or":
            res = il.or_expr(4, left, right)
        elif name == "xor":
            res = il.xor_expr(4, left, right)
        elif name == "shl":
            res = il.shift_left(4, left, right)
        elif name in ("shr", "shr.un"):
            res = (
                il.logical_shift_right(4, left, right)
                if name == "shr.un"
                else il.arith_shift_right(4, left, right)
            )
        else:
            res = il.add(4, left, right)

        il.append(il.set_reg(4, left_reg, res))

    elif name in ("neg", "not"):
        src_reg = _eval(height - 1)
        src = il.reg(4, src_reg)
        res = il.neg_expr(4, src) if name == "neg" else il.not_expr(4, src)
        il.append(il.set_reg(4, src_reg, res))

    # Comparisons
    elif name in ("ceq", "cgt", "cgt.un", "clt", "clt.un", "ckfinite"):
        left_reg = _eval(height - 2)
        right_reg = _eval(height - 1)
        left = il.reg(4, left_reg)
        right = il.reg(4, right_reg)

        if name == "ceq":
            res = il.compare_equal(4, left, right)
        elif name in ("cgt", "cgt.un"):
            res = (
                il.compare_unsigned_greater_than(4, left, right)
                if name == "cgt.un"
                else il.compare_signed_greater_than(4, left, right)
            )
        elif name in ("clt", "clt.un"):
            res = (
                il.compare_unsigned_less_than(4, left, right)
                if name == "clt.un"
                else il.compare_signed_less_than(4, left, right)
            )
        else:
            res = il.compare_equal(4, left, right)

        il.append(il.set_reg(4, left_reg, res))

    # Unconditional Control Flow
    elif name in ("br", "br.s", "leave", "leave.s"):
        target = _resolve_target(operand, is_relative=True)
        if name in ("leave", "leave.s") and il.source_function:
            target = _leave_destination(il.source_function.view, addr, target)
        il.append(il.jump(il.const_pointer(arch.address_size, target)))

    # Conditional Control Flow
    elif name in ("brtrue", "brtrue.s"):
        target = _resolve_target(operand, is_relative=True)
        fallthrough = addr + length
        _emit_branch_if(target, fallthrough, invert=False)

    elif name in ("brfalse", "brfalse.s"):
        target = _resolve_target(operand, is_relative=True)
        fallthrough = addr + length
        _emit_branch_if(target, fallthrough, invert=True)

    elif name in (
        "beq",
        "beq.s",
        "bge",
        "bge.s",
        "bge.un",
        "bge.un.s",
        "bgt",
        "bgt.s",
        "bgt.un",
        "bgt.un.s",
        "ble",
        "ble.s",
        "ble.un",
        "ble.un.s",
        "blt",
        "blt.s",
        "blt.un",
        "blt.un.s",
        "bne.un",
        "bne.un.s",
    ):
        target = _resolve_target(operand, is_relative=True)
        fallthrough = addr + length
        left_reg = _eval(height - 2)
        right_reg = _eval(height - 1)
        left = il.reg(4, left_reg)
        right = il.reg(4, right_reg)

        if name in ("beq", "beq.s"):
            cond = il.compare_equal(4, left, right)
        elif name in ("bge", "bge.s"):
            cond = il.compare_signed_greater_equal(4, left, right)
        elif name in ("bge.un", "bge.un.s"):
            cond = il.compare_unsigned_greater_equal(4, left, right)
        elif name in ("bgt", "bgt.s"):
            cond = il.compare_signed_greater_than(4, left, right)
        elif name in ("bgt.un", "bgt.un.s"):
            cond = il.compare_unsigned_greater_than(4, left, right)
        elif name in ("ble", "ble.s"):
            cond = il.compare_signed_less_equal(4, left, right)
        elif name in ("ble.un", "ble.un.s"):
            cond = il.compare_unsigned_less_equal(4, left, right)
        elif name in ("blt", "blt.s"):
            cond = il.compare_signed_less_than(4, left, right)
        elif name in ("blt.un", "blt.un.s"):
            cond = il.compare_unsigned_less_than(4, left, right)
        else:
            cond = il.compare_not_equal(4, left, right)

        _emit_branch_if(target, fallthrough, cond_expr=cond)

    elif name == "switch":
        selector = il.reg(4, _eval(height - 1))
        base_addr = addr + length
        targets = {}
        for index, offset in enumerate(operand or ()):
            label = il.get_label_for_address(arch, base_addr + offset)
            if label is not None:
                targets[index] = label
        if targets:
            il.append(il.jump_to(selector, targets))
        else:
            il.append(il.nop())

    elif name == "endfinally":
        continuation = (
            _finally_destination(il.source_function.view, addr)
            if il.source_function else None
        )
        if continuation is None:
            il.append(il.trap(2))
        else:
            il.append(il.jump(il.const_pointer(arch.address_size, continuation)))

    elif name in ("throw", "rethrow", "endfilter"):
        # LLIL_TRAP is terminal and is available across supported Binary Ninja
        # versions. Distinct values preserve the CIL terminal category.
        trap_values = {"throw": 0, "rethrow": 1, "endfilter": 3}
        il.append(il.trap(trap_values[name]))

    elif name == "jmp":
        target_vaddr = (
            token_map.get(operand)
            if operand is not None
            else _resolve_target(operand, is_relative=True)
        )
        il.append(il.jump(il.const_pointer(arch.address_size, target_vaddr if target_vaddr else 0)))

    # Calls & Invocations
    elif name in ("call", "callvirt", "newobj", "calli"):
        target_vaddr = token_map.get(operand) if operand is not None else 0
        if not target_vaddr and isinstance(operand, int) and operand:
            target_vaddr = (
                0x50000000
                + (operand & 0x00FFFFFF) * arch.address_size
            )

        target = None
        if il.source_function and operand is not None:
            target = il.source_function.view.session_data.get("token_targets", {}).get(operand)
        signature = getattr(target, "signature", None)
        pushes = 1 if name == "newobj" else 0
        pops = 0
        if isinstance(signature, MethodSignature):
            pops, pushes = stack_effect(signature, name)

        # LLIL calls infer arguments from calling-convention locations, not
        # from the CIL evaluation stack. Marshal stack values explicitly in
        # reverse order so the first declared argument occupies the first
        # incoming stack slot.
        argument_indices = call_argument_indices(height, pops, name == "calli")
        for stack_index in reversed(argument_indices):
            il.append(
                il.push(
                    arch.address_size,
                    il.reg(arch.address_size, _eval(stack_index)),
                )
            )

        if name == "calli":
            destination = il.reg(arch.address_size, _eval(height - 1))
        else:
            destination = il.const_pointer(
                arch.address_size, target_vaddr if target_vaddr else 0
            )

        if target_vaddr or name == "calli":
            il.append(il.call(destination))
            if argument_indices:
                il.append(
                    il.set_reg(
                        arch.address_size,
                        "sp",
                        il.add(
                            arch.address_size,
                            il.reg(arch.address_size, "sp"),
                            il.const(
                                arch.address_size,
                                len(argument_indices) * arch.address_size,
                            ),
                        ),
                    )
                )
            if pushes:
                il.append(
                    il.set_reg(
                        arch.address_size,
                        _eval(height - pops),
                        il.reg(arch.address_size, "ret"),
                    )
                )
        else:
            il.append(il.call(destination))

    # Memory & Pointer Operations
    elif name == "newarr":
        slot = _eval(height - 1)
        allocation = il.sub(
            arch.address_size,
            il.reg(arch.address_size, "sp"),
            il.const(arch.address_size, 0x1000 + ((addr & 0xfff) << 4)),
        )
        il.append(il.store(
            4,
            il.sub(
                arch.address_size, allocation,
                il.const(arch.address_size, 4),
            ),
            il.reg(4, slot),
        ))
        il.append(il.set_reg(arch.address_size, slot, allocation))

    elif name == "ldlen":
        slot = _eval(height - 1)
        length_address = il.sub(
            arch.address_size,
            il.reg(arch.address_size, slot),
            il.const(arch.address_size, 4),
        )
        il.append(il.set_reg(
            arch.address_size, slot,
            il.zero_extend(arch.address_size, il.load(4, length_address)),
        ))

    elif name.startswith("stelem.") or name == "stelem":
        size = array_element_size(name, arch.address_size)
        array = il.reg(arch.address_size, _eval(height - 3))
        index = il.reg(arch.address_size, _eval(height - 2))
        address = il.add(
            arch.address_size, array,
            il.mult(
                arch.address_size, index,
                il.const(arch.address_size, size),
            ),
        )
        il.append(il.store(size, address, il.reg(size, _eval(height - 1))))

    elif name.startswith("ldelem.") or name in ("ldelem", "ldelema"):
        size = array_element_size(name, arch.address_size)
        destination = _eval(height - 2)
        array = il.reg(arch.address_size, destination)
        index = il.reg(arch.address_size, _eval(height - 1))
        address = il.add(
            arch.address_size, array,
            il.mult(
                arch.address_size, index,
                il.const(arch.address_size, size),
            ),
        )
        value = address if name == "ldelema" else il.load(size, address)
        il.append(il.set_reg(
            arch.address_size if name == "ldelema" else size,
            destination, value,
        ))

    elif name.startswith("conv."):
        slot = _eval(height - 1)
        size = array_element_size(name, arch.address_size)
        source = il.reg(min(size, arch.address_size), slot)
        il.append(il.set_reg(size, slot, source))

    elif name.startswith("ldind."):
        slot = _eval(height - 1)
        size = array_element_size(name, arch.address_size)
        il.append(il.set_reg(size, slot, il.load(
            size, il.reg(arch.address_size, slot)
        )))

    elif name.startswith("stind."):
        size = array_element_size(name, arch.address_size)
        il.append(il.store(
            size,
            il.reg(arch.address_size, _eval(height - 2)),
            il.reg(size, _eval(height - 1)),
        ))

    elif name in (
        "cpobj",
        "cpblk",
        "initblk",
        "refanytype",
        "refanyval",
        "mkrefany",
        "ldobj",
    ):
        if name in ("cpobj", "cpblk", "initblk"):
            il.append(il.nop())
        else:
            il.append(
                il.set_reg(arch.address_size, _eval(height), il.reg(arch.address_size, _eval(height - 1)))
            )

    # Returns
    elif name == "ret":
        signature = None
        if il.source_function:
            signature = il.source_function.view.session_data.get(
                "method_signatures", {}
            ).get(il.source_function.start)
        if (
            height > 0
            and isinstance(signature, MethodSignature)
            and not signature.return_type.is_void
        ):
            result_size = native_width(signature.return_type, arch.address_size)
            result = il.reg(result_size, _eval(height - 1))
            il.append(il.set_reg(result_size, "ret", result))
        # LLIL_RET's expression is the native return address, not the managed
        # return value. Calls place that address at the incoming stack top.
        il.append(il.ret(il.pop(arch.address_size)))

    else:
        il.append(il.nop())

    return length
