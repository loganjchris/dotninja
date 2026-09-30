"""Pure analysis primitives shared by lifting, validation, and deobfuscation."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import time
from typing import Any, Hashable, Sequence


@dataclass(frozen=True)
class StackValue:
    kind: str = "unknown"
    width: int | None = None


class StackMergeError(ValueError):
    pass


def merge_stack_states(left: Sequence[StackValue], right: Sequence[StackValue]) -> tuple[StackValue, ...]:
    if len(left) != len(right):
        raise StackMergeError(f"stack-depth conflict: {len(left)} != {len(right)}")
    merged = []
    for a, b in zip(left, right):
        if a == b:
            merged.append(a)
        elif a.kind == "unknown":
            merged.append(b)
        elif b.kind == "unknown":
            merged.append(a)
        elif a.width == b.width:
            merged.append(StackValue("unknown", a.width))
        else:
            raise StackMergeError(f"incompatible stack values: {a} != {b}")
    return tuple(merged)


def propagate_stack_states(entry: Hashable, successors, transfer):
    states: dict[Hashable, tuple[StackValue, ...]] = {entry: ()}
    work = deque([entry])
    diagnostics: list[str] = []
    while work:
        node = work.popleft()
        outgoing = tuple(transfer(node, states[node]))
        for target, seeded in successors(node, outgoing):
            candidate = tuple(seeded)
            if target not in states:
                states[target] = candidate
                work.append(target)
                continue
            try:
                merged = merge_stack_states(states[target], candidate)
            except StackMergeError as exc:
                diagnostics.append(f"{target}: {exc}")
                continue
            if merged != states[target]:
                states[target] = merged
                work.append(target)
    return states, diagnostics


class EmulationError(ValueError):
    pass


def emulate_pure_cil(instructions: Sequence[tuple], arguments: Sequence[object] = (), *, instruction_budget: int = 10000, time_budget: float = 0.25):
    """Bounded emulator for deterministic, side-effect-free decryptor subsets."""
    start = time.monotonic()
    stack: list[Any] = []
    locals_: dict[int, Any] = {}
    pc = 0
    steps = 0
    while 0 <= pc < len(instructions):
        steps += 1
        if steps > instruction_budget or time.monotonic() - start > time_budget:
            raise EmulationError("emulation budget exceeded")
        ins = instructions[pc]
        op = str(ins[0]).lower()
        arg: Any = ins[1] if len(ins) > 1 else None
        pc += 1
        if op in {"nop", "conv.i4", "conv.u4"}:
            continue
        if op.startswith("ldc.i4"):
            stack.append(int(arg or 0))
        elif op == "ldstr":
            stack.append(str(arg))
        elif op == "ldarg":
            stack.append(arguments[int(arg)])
        elif op == "ldloc":
            stack.append(locals_[int(arg)])
        elif op == "stloc":
            locals_[int(arg)] = stack.pop()
        elif op in {"add", "sub", "mul", "xor", "and", "or", "rem", "div"}:
            b, a = stack.pop(), stack.pop()
            operations = {"add": lambda: a+b, "sub": lambda: a-b, "mul": lambda: a*b,
                          "xor": lambda: a^b, "and": lambda: a&b, "or": lambda: a|b,
                          "rem": lambda: a%b, "div": lambda: a//b}
            stack.append(operations[op]())
        elif op == "newarr":
            stack.append([0] * int(stack.pop()))
        elif op == "ldlen":
            stack.append(len(stack.pop()))
        elif op == "ldelem":
            index, array = int(stack.pop()), stack.pop()
            stack.append(array[index])
        elif op == "stelem":
            value, index, array = stack.pop(), int(stack.pop()), stack.pop()
            array[index] = value
        elif op == "br":
            pc = int(arg)
        elif op in {"brtrue", "brfalse"}:
            condition = bool(stack.pop())
            if condition == (op == "brtrue"):
                pc = int(arg)
        elif op == "ret":
            return stack.pop() if stack else None
        else:
            raise EmulationError(f"unsupported instruction: {op}")
    raise EmulationError("method did not return")
