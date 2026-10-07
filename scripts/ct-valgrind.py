#!/usr/bin/env python3
"""Fail closed on Memcheck errors except verified GCC strub zero-store sites.

No Valgrind suppression is used: even another InvalidWrite in the same function
fails. This deliberately recognizes only the pinned x86-64 GNU objdump pattern;
a toolchain change needs fresh inspection before extending the exception.
"""

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET


PREFIX = "blake2b__hashing__"
WRAPPERS = tuple(PREFIX + name for name in ("hash", "hash__2", "init", "update", "final"))


class CheckFailure(ValueError):
    """The evidence does not meet the gate's conservative contract."""


def require(condition, message):
    if not condition:
        raise CheckFailure(message)


@dataclass(frozen=True)
class Instruction:
    address: int
    operation: str
    operands: str


def disassembly_functions(text):
    require("file format elf64-x86-64" in text, "expected GNU ELF x86-64 disassembly")
    functions = {}
    current = None
    for line in text.splitlines():
        header = re.fullmatch(r"\s*([0-9a-fA-F]+) <([^>]+)>:\s*", line)
        if header:
            name = header[2]
            # GNU objdump may repeat unrelated local C-runtime symbol names.
            # Hashing wrappers and clones must remain unambiguous.
            require(name not in functions or not name.startswith(PREFIX),
                    f"duplicate disassembly symbol: {name}")
            current = (int(header[1], 16), [])
            functions[name] = current
            continue
        address = re.match(r"\s*([0-9a-fA-F]+):\s*(.*?)\s*$", line)
        if address:
            require(current is not None, "instruction outside a function")
            body = address[2].split("#", 1)[0].strip()
            parsed = re.fullmatch(r"([a-z][a-z0-9]*)\s*(.*)", body)
            require(parsed is not None, "expected --no-show-raw-insn instruction text")
            instruction = Instruction(int(address[1], 16), parsed[1], re.sub(r"\s+", "", parsed[2]))
            require(not current[1] or instruction.address > current[1][-1].address,
                    "non-increasing instruction addresses")
            current[1].append(instruction)
        elif current is not None and line.strip():
            # GNU headings begin a new section. Anything resembling an omitted
            # instruction is unsafe to skip inside a function's instruction list.
            require(line.startswith("Disassembly of section "), "unrecognized disassembly line")
            current = None
    require(bool(functions), "empty disassembly")
    for name in WRAPPERS:
        require(name in functions and functions[name][1], f"missing wrapper: {name}")
        require(functions[name][0] == functions[name][1][0].address, f"missing function entry: {name}")
    return functions


def branch_target(instruction):
    target = re.fullmatch(r"([0-9a-fA-F]+)<([^>]+)>", instruction.operands)
    require(target is not None, "unrecognized branch/call target")
    return int(target[1], 16), target[2]


def scrubbing_sites(text, mode):
    functions = disassembly_functions(text)
    if mode == "plain":
        require(".strub." not in text, "plain binary still contains strub clones/references")
        # Without clones, this pattern cannot have a sanctioned scrub loop.
        for name in WRAPPERS:
            instructions = functions[name][1]
            require(not any(i.operation == "movq" and i.operands == "$0x0,(%rax)"
                            and p.operation == "sub" and p.operands == "$0x8,%rax"
                            for p, i in zip(instructions, instructions[1:])),
                    f"plain wrapper contains a scrubbing loop: {name}")
        return {}

    sites = {}
    for name in WRAPPERS:
        instructions = functions[name][1]
        expected_clone = PREFIX + ("digest_of" if name in WRAPPERS[:2] else name.removeprefix(PREFIX))
        found = []
        for start, call in enumerate(instructions):
            if call.operation != "call":
                continue
            target, symbol = branch_target(call)
            if not re.fullmatch(re.escape(expected_clone) + r"\.strub\.[0-9]+", symbol):
                continue
            require(symbol in functions and functions[symbol][0] == target,
                    f"missing/mismatched strub clone: {symbol}")
            sequence = instructions[start:start + 11]
            require(len(sequence) >= 10, f"truncated strub epilogue: {name}")
            load = sequence[1]
            require(load.operation == "mov" and load.operands in ("-0x8(%rbp),%rdx", "0x8(%rsp),%rdx"),
                    f"unexpected strub watermark load: {name}")
            optional_add = sequence[2].operation == "add"
            offset = 3 if optional_add else 2
            if optional_add:
                require(sequence[2].operands == "$0x20,%rsp", f"unexpected strub stack adjustment: {name}")
            expected = (("mov", "%rsp,%rax"), ("cmp", "%rsp,%rdx"), ("jae", None),
                        ("sub", "$0x8,%rax"), ("movq", "$0x0,(%rax)"),
                        ("cmp", "%rax,%rdx"), ("jb", None))
            loop = sequence[offset:offset + 7]
            require(len(loop) == 7, f"truncated strub loop: {name}")
            for instruction, (operation, operands) in zip(loop, expected):
                require(instruction.operation == operation and (operands is None or instruction.operands == operands),
                        f"unrecognized strub instruction at {instruction.address:#x}: {name}")
            end_index = start + offset + 7
            require(end_index < len(instructions), f"missing strub loop end: {name}")
            end = instructions[end_index]
            require(branch_target(loop[2]) == (end.address, f"{name}+0x{end.address-functions[name][0]:x}"),
                    f"unexpected strub forward branch: {name}")
            require(branch_target(loop[6]) == (loop[3].address, f"{name}+0x{loop[3].address-functions[name][0]:x}"),
                    f"unexpected strub back branch: {name}")
            # Exact lengths also prevent a missing/unparsed instruction in the
            # supposedly contiguous sequence from broadening the exception.
            lengths = [5, 4 if load.operands.startswith("-") else 5]
            if optional_add:
                lengths.append(4)
            lengths.extend((3, 3, 2, 4, 7, 3, 2))
            segment = instructions[start:end_index + 1]
            require(all(b.address - a.address == length for a, b, length in zip(segment, segment[1:], lengths)),
                    f"non-contiguous strub epilogue: {name}")
            interior = {i.address for i in segment[1:-1]}
            for instruction in instructions:
                if instruction.operation.startswith("j") and instruction not in (loop[2], loop[6]):
                    require(branch_target(instruction)[0] not in interior, f"unexpected entry into strub loop: {name}")
            found.append(loop[4].address)
        require(len(found) == 1, f"expected exactly one verified scrubbing loop: {name}")
        sites[name] = found[0]
    return sites


def one_text(element, path):
    matches = element.findall(path)
    require(len(matches) == 1 and matches[0].text is not None, f"missing/duplicate XML field: {path}")
    return matches[0].text.strip()


def read_report(text):
    require("<!DOCTYPE" not in text and "<!ENTITY" not in text, "XML declarations/entities are unsupported")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as error:
        raise CheckFailure(f"invalid/truncated Valgrind XML: {error}") from error
    require(root.tag == "valgrindoutput", "not a Valgrind report")
    protocol = one_text(root, "protocolversion")
    require(protocol in ("4", "6"), "unsupported Valgrind XML protocol")
    require(one_text(root, "protocoltool") == "memcheck", "report tool is not Memcheck")
    states = [one_text(status, "state") for status in root.findall("status")]
    require(states == ["RUNNING", "FINISHED"], "Valgrind did not complete normally")
    require(not root.findall(".//fatal_signal"), "Valgrind report contains a fatal signal")
    require(len(root.findall("suppcounts")) == 1, "missing/duplicate suppression counts")
    require(not list(root.find("suppcounts")), "Valgrind used suppressions")
    errors = root.findall("error")
    ids = [one_text(error, "unique") for error in errors]
    require(len(ids) == len(set(ids)), "duplicate Valgrind error identity")
    require(len(root.findall("errorcounts")) == 1, "missing/duplicate error counts")
    counts = {}
    for pair in root.find("errorcounts"):
        require(pair.tag == "pair", "unexpected error count record")
        unique = one_text(pair, "unique")
        value = one_text(pair, "count")
        require(unique not in counts and re.fullmatch(r"[1-9][0-9]*", value) is not None, "invalid error count")
        counts[unique] = int(value)
    require(set(counts) == set(ids), "error details and counts disagree")
    # Protocol 6 adds this independent accounting record. It must agree with
    # the contexts above; otherwise discarded/unreported errors could vanish.
    summaries = root.findall("error_summary")
    if protocol == "6" or summaries:
        require(len(summaries) == 1, "missing/duplicate error summary")
        summary = summaries[0]
        expected = {"errors": sum(counts.values()), "error_contexts": len(errors),
                    "suppressed": 0, "suppressed_contexts": 0}
        require(len(summary) == len(expected) and {child.tag for child in summary} == set(expected),
                "unexpected error summary fields")
        for field, count in expected.items():
            value = one_text(summary, field)
            require(not list(summary.find(field)) and re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is not None,
                    f"malformed error summary field: {field}")
            require(int(value) == count, f"error summary disagrees: {field}")
    return errors, counts


def stack_frame(stack, binary):
    frames = stack.findall("frame")
    require(bool(frames), "error has no stack frame")
    frame = frames[0]
    object_name = one_text(frame, "obj")
    require(Path(object_name).is_absolute() and Path(object_name).resolve() == binary,
            "error top frame belongs to another binary")
    ip_text = one_text(frame, "ip")
    require(re.fullmatch(r"0x[0-9a-fA-F]+", ip_text) is not None, "invalid error instruction address")
    return one_text(frame, "fn"), int(ip_text, 16)


def binary_frame(error, binary, expected_negative=False):
    # --track-origins places a second direct stack after auxwhat. Keep its
    # frames separate from the primary fault stack rather than flattening XML.
    children = list(error)
    detail_index = next((i for i, child in enumerate(children) if child.tag in ("auxwhat", "xauxwhat")), len(children))
    primary = [(i, child) for i, child in enumerate(children[:detail_index]) if child.tag == "stack"]
    require(len(primary) == 1, "missing/duplicate primary error stack")
    index, stack = primary[0]
    fn, ip = stack_frame(stack, binary)
    if expected_negative and fn == "ct_negative_branch":
        require([child.tag for child in children[index:]] == ["stack", "auxwhat", "stack"],
                "unexpected negative-control origin structure")
        require(one_text(error, "auxwhat") == "Uninitialised value was created by a client request",
                "unexpected negative-control origin description")
        origin_fn, _ = stack_frame(children[-1], binary)
        require(origin_fn == "ct_negative_control", "unexpected negative-control origin function")
    else:
        require(len(error.findall("stack")) == 1, "unexpected extra error stack")
    return fn, ip


def check(xml_text, assembly, binary, mode, expect_secret_branch=False):
    require(binary.is_absolute(), "--binary must be absolute")
    binary = binary.resolve()
    require(binary.is_file(), "binary is missing or not a regular file")
    with binary.open("rb") as executable:
        header = executable.read(64)
    require(len(header) == 64 and header[:7] == b"\x7fELF\x02\x01\x01"
            and header[16:20] == b"\x02\x00\x3e\x00",
            "binary must be a non-PIE ELF64 x86-64 executable")
    sites = scrubbing_sites(assembly, mode)
    errors, counts = read_report(xml_text)
    permitted = []
    negative = []
    for error in errors:
        kind = one_text(error, "kind")
        fn, ip = binary_frame(error, binary, expect_secret_branch and kind == "UninitCondition")
        unique = one_text(error, "unique")
        if expect_secret_branch and kind == "UninitCondition" and fn == "ct_negative_branch":
            require(one_text(error, "what") == "Conditional jump or move depends on uninitialised value(s)",
                    "unexpected negative-control error description")
            negative.append((ip, counts[unique]))
            continue
        require(mode == "hardened" and kind == "InvalidWrite", f"unexpected Memcheck {kind} in {fn} at {ip:#x}")
        require(one_text(error, "what") == "Invalid write of size 8", "unexpected invalid-write size/description")
        require(fn in sites and ip == sites[fn], f"write is not a verified strub zero-store: {fn} at {ip:#x}")
        details = [element.text.strip() if element.text else "" for element in error.findall("auxwhat")]
        require(len(details) == 2 and re.fullmatch(r"Address 0x[0-9a-fA-F]+ is on thread [1-9][0-9]*'s stack", details[0])
                and details[1] == "136 bytes below stack pointer", "unfamiliar strub write address/distance")
        permitted.append((fn, ip, counts[unique]))
    require(not expect_secret_branch or bool(negative), "negative control did not report its secret-dependent branch")
    for fn, ip, count in permitted:
        print(f"verified strub zero-store: {fn} at {ip:#x} ({count} reports)")
    if negative:
        print(f"negative control detected: {len(negative)} secret-branch contexts")
    print(f"Memcheck {mode} {'negative control' if expect_secret_branch else 'gate'} passed: "
          f"{len(permitted)} verified scrubbing contexts; no unexpected errors")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xml", type=Path, required=True)
    parser.add_argument("--disassembly", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--mode", choices=("plain", "hardened"), required=True)
    parser.add_argument("--expect-secret-branch", action="store_true")
    args = parser.parse_args()
    try:
        check(args.xml.read_text(), args.disassembly.read_text(), args.binary, args.mode, args.expect_secret_branch)
    except (CheckFailure, OSError, UnicodeError) as error:
        print(f"Memcheck gate failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
