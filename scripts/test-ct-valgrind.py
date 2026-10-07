#!/usr/bin/env python3
"""Adversarial fixtures for the narrowly scoped Memcheck gate."""

import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET


spec = importlib.util.spec_from_file_location("ct_valgrind", Path(__file__).with_name("ct-valgrind.py"))
gate = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = gate
spec.loader.exec_module(gate)
BINARY_DIRECTORY = tempfile.TemporaryDirectory()
BINARY = Path(BINARY_DIRECTORY.name) / "ct-main"
ELF_HEADER = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x02\x00\x3e\x00" + b"\x00" * 44
BINARY.write_bytes(ELF_HEADER)


def assembly(hardened=True):
    """Reproduce GNAT 16.1's five wrapper epilogues, including real lengths."""
    lines = ["/tmp/ct-main: file format elf64-x86-64", "Disassembly of section .text:"]
    sites = {}
    for index, name in enumerate(gate.WRAPPERS):
        base = 0x401000 + index * 0x100
        lines.append(f"{base:016x} <{name}>:")
        if not hardened:
            lines.append(f" {base:x}: ret")
            continue
        clone = "digest_of" if index < 2 else name.removeprefix(gate.PREFIX)
        clone = gate.PREFIX + clone + ".strub.0"
        clone_address = 0x403000 if index < 2 else 0x403000 + index * 0x100
        instructions = [(5, "call", f"{clone_address:x} <{clone}>")]
        instructions.append((4 if index < 2 else 5, "mov", "-0x8(%rbp),%rdx" if index < 2 else "0x8(%rsp),%rdx"))
        if index < 2:
            instructions.append((4, "add", "$0x20,%rsp"))
        instructions.extend([(3, "mov", "%rsp,%rax"), (3, "cmp", "%rsp,%rdx"), (2, "jae", "END"),
                             (4, "sub", "$0x8,%rax"), (7, "movq", "$0x0,(%rax)"),
                             (3, "cmp", "%rax,%rdx"), (2, "jb", "START"), (1, "ret", "")])
        addresses = []
        cursor = base
        for length, operation, operands in instructions:
            addresses.append(cursor)
            cursor += length
        end = addresses[-1]
        start = addresses[next(i for i, (_, op, _) in enumerate(instructions) if op == "sub")]
        for address, (_, operation, operands) in zip(addresses, instructions):
            if operands == "END":
                operands = f"{end:x} <{name}+0x{end-base:x}>"
            elif operands == "START":
                operands = f"{start:x} <{name}+0x{start-base:x}>"
            if operation == "movq":
                sites[name] = address
            lines.append(f" {address:x}: {operation} {operands}")
    if hardened:
        for index, name in enumerate(("digest_of", "init", "update", "final")):
            address = 0x403000 if index == 0 else 0x403100 + index * 0x100
            lines.extend((f"{address:016x} <{gate.PREFIX}{name}.strub.0>:", f" {address:x}: ret"))
    return "\n".join(lines), sites


def report(errors=()):
    root = ET.Element("valgrindoutput")
    ET.SubElement(root, "protocolversion").text = "4"
    ET.SubElement(root, "protocoltool").text = "memcheck"
    ET.SubElement(ET.SubElement(root, "status"), "state").text = "RUNNING"
    for error in errors:
        root.append(error)
    ET.SubElement(ET.SubElement(root, "status"), "state").text = "FINISHED"
    counts = ET.SubElement(root, "errorcounts")
    for error in errors:
        pair = ET.SubElement(counts, "pair")
        ET.SubElement(pair, "count").text = "100"
        ET.SubElement(pair, "unique").text = error.findtext("unique")
    ET.SubElement(root, "suppcounts")
    return root


def error_record(fn, ip, kind="InvalidWrite", unique="0x1"):
    error = ET.Element("error")
    ET.SubElement(error, "unique").text = unique
    ET.SubElement(error, "kind").text = kind
    ET.SubElement(error, "what").text = ("Invalid write of size 8" if kind == "InvalidWrite" else
                                         "Conditional jump or move depends on uninitialised value(s)")
    frame = ET.SubElement(ET.SubElement(error, "stack"), "frame")
    for tag, value in (("fn", fn), ("ip", hex(ip)), ("obj", str(BINARY))):
        ET.SubElement(frame, tag).text = value
    if kind == "InvalidWrite":
        ET.SubElement(error, "auxwhat").text = "Address 0x1fff000818 is on thread 1's stack"
        ET.SubElement(error, "auxwhat").text = "136 bytes below stack pointer"
    if kind == "UninitCondition" and fn == "ct_negative_branch":
        ET.SubElement(error, "auxwhat").text = "Uninitialised value was created by a client request"
        origin = ET.SubElement(ET.SubElement(error, "stack"), "frame")
        for tag, value in (("fn", "ct_negative_control"), ("ip", hex(ip + 16)), ("obj", str(BINARY))):
            ET.SubElement(origin, tag).text = value
    return error


class GateTests(unittest.TestCase):
    def setUp(self):
        self.assembly, self.sites = assembly()
        self.plain, _ = assembly(False)
        self.error = error_record(gate.WRAPPERS[0], self.sites[gate.WRAPPERS[0]])
        self.root = report((self.error,))

    def check(self, root=None, assembly_text=None, mode="hardened", negative=False):
        with contextlib.redirect_stdout(io.StringIO()):
            gate.check(ET.tostring(root if root is not None else self.root, encoding="unicode"),
                       assembly_text if assembly_text is not None else self.assembly, BINARY, mode, negative)

    def reject(self, root=None, assembly_text=None, mode="hardened", negative=False):
        with self.assertRaises(gate.CheckFailure):
            self.check(root, assembly_text, mode, negative)

    def test_all_five_sites_allowed(self):
        errors = [error_record(name, site, unique=hex(i + 1)) for i, (name, site) in enumerate(self.sites.items())]
        self.check(report(errors))

    def test_plain_without_errors_passes(self):
        self.check(report(), self.plain, "plain")

    def test_hardened_without_errors_passes(self):
        self.check(report())

    def test_plain_rejects_invalid_write(self):
        self.reject(assembly_text=self.plain, mode="plain")

    def test_plain_rejects_strub(self):
        self.reject(report(), mode="plain")

    def test_other_error_kinds_never_allowed(self):
        for kind in ("InvalidRead", "UninitCondition", "UninitValue", "Leak_DefinitelyLost", "InvalidFree"):
            with self.subTest(kind=kind):
                self.root.find("error/kind").text = kind
                self.reject()

    def test_unrelated_instruction_same_wrapper_fails(self):
        self.root.find("error/stack/frame/ip").text = hex(self.sites[gate.WRAPPERS[0]] + 7)
        self.reject()

    def test_unrelated_zero_store_same_wrapper_fails(self):
        fn = gate.WRAPPERS[0]
        marker = f"{0x401100:016x} <{gate.WRAPPERS[1]}>:"
        modified = self.assembly.replace(marker, f" 401080: movq $0x0,(%rax)\n{marker}")
        self.root.find("error/stack/frame/ip").text = "0x401080"
        self.reject(assembly_text=modified)

    def test_wrapper_suffix_and_other_functions_fail(self):
        for fn in (gate.WRAPPERS[0] + ".cold", gate.WRAPPERS[0] + ".strub.0", "ct_negative_branch"):
            with self.subTest(fn=fn):
                self.root.find("error/stack/frame/fn").text = fn
                self.reject()

    def test_duplicate_primary_stack_fails(self):
        error = self.root.find("error")
        error.append(ET.fromstring(ET.tostring(error.find("stack"))))
        self.reject()

    def test_other_binary_fails(self):
        self.root.find("error/stack/frame/obj").text = "/tmp/another-ct-main"
        self.reject()

    def test_relative_binary_object_fails(self):
        self.root.find("error/stack/frame/obj").text = "ct-main"
        self.reject()

    def test_symlink_resolves_to_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / "binary"
            real.write_bytes(ELF_HEADER)
            alias = Path(directory) / "alias"
            alias.symlink_to(real)
            self.root.find("error/stack/frame/obj").text = str(alias)
            with contextlib.redirect_stdout(io.StringIO()):
                gate.check(ET.tostring(self.root, encoding="unicode"), self.assembly, real, "hardened")

    def test_write_size_fails(self):
        self.root.find("error/what").text = "Invalid write of size 4"
        self.reject()

    def test_distance_mismatch_fails(self):
        self.root.findall("error/auxwhat")[1].text = "144 bytes below stack pointer"
        self.reject()

    def test_non_stack_address_fails(self):
        self.root.findall("error/auxwhat")[0].text = "Address 0x1fff000818 is inside a freed block"
        self.reject()

    def test_missing_distance_fails(self):
        self.root.find("error").remove(self.root.findall("error/auxwhat")[1])
        self.reject()

    def test_forward_branch_target_fails(self):
        modified = self.assembly.replace("jae 401025", "jae 401024", 1)
        self.assertNotEqual(modified, self.assembly)
        self.reject(assembly_text=modified)

    def test_backward_branch_target_fails(self):
        modified = self.assembly.replace("jb 401015", "jb 401016", 1)
        self.assertNotEqual(modified, self.assembly)
        self.reject(assembly_text=modified)

    def test_missing_loop_instruction_fails(self):
        self.reject(assembly_text=self.assembly.replace(" 401015: sub $0x8,%rax\n", "", 1))

    def test_intervening_call_fails(self):
        self.reject(assembly_text=self.assembly.replace("mov %rsp,%rax", "call 403000 <blake2b__hashing__digest_of.strub.0>", 1))

    def test_loop_entry_from_outside_fails(self):
        marker = f"{0x401100:016x} <{gate.WRAPPERS[1]}>:"
        modified = self.assembly.replace(marker, " 401080: jmp 401015 <blake2b__hashing__hash+0x15>\n" + marker)
        self.reject(assembly_text=modified)

    def test_unrelated_duplicate_local_symbols_allowed(self):
        extra = "\n0000000000405000 <runtime_local>:\n 405000: ret\n0000000000405010 <runtime_local>:\n 405010: ret"
        self.check(assembly_text=self.assembly + extra)

    def test_duplicate_wrapper_fails(self):
        extra = "\n0000000000405000 <blake2b__hashing__hash>:\n 405000: ret"
        self.reject(assembly_text=self.assembly + extra)

    def test_missing_clone_fails(self):
        self.reject(assembly_text=self.assembly.replace("<blake2b__hashing__digest_of.strub.0>:\n 403000: ret", "<other>:\n 403000: ret"))

    def test_mismatched_clone_target_fails(self):
        self.reject(assembly_text=self.assembly.replace("call 403000", "call 403001", 1))

    def test_missing_wrapper_fails(self):
        self.reject(assembly_text=self.assembly.replace("<blake2b__hashing__final>:", "<other_final>:"))

    def test_unparsed_or_raw_instruction_fails(self):
        for replacement in ("?? omitted", "48 89 e0 mov %rsp,%rax"):
            with self.subTest(replacement=replacement):
                self.reject(assembly_text=self.assembly.replace("mov %rsp,%rax", replacement, 1))

    def protocol_six(self, root=None):
        root = root if root is not None else self.root
        root.find("protocolversion").text = "6"
        summary = ET.SubElement(root, "error_summary")
        values = {"errors": sum(int(pair.findtext("count")) for pair in root.find("errorcounts")),
                  "error_contexts": len(root.findall("error")), "suppressed": 0, "suppressed_contexts": 0}
        for field, value in values.items():
            ET.SubElement(summary, field).text = str(value)
        return root

    def test_protocol_six_complete_summary_passes(self):
        self.check(self.protocol_six())
        self.check(self.protocol_six(report()), self.plain, "plain")

    def test_protocol_five_and_unknown_versions_fail(self):
        for version in ("5", "7", "06", ""):
            with self.subTest(version=version):
                self.root.find("protocolversion").text = version
                self.reject()

    def test_protocol_six_missing_summary_fails(self):
        self.root.find("protocolversion").text = "6"
        self.reject()

    def test_protocol_six_mismatched_counts_and_suppression_fail(self):
        for field, wrong in (("errors", "99"), ("errors", "101"), ("error_contexts", "0"),
                             ("error_contexts", "2"), ("suppressed", "1"), ("suppressed_contexts", "1")):
            with self.subTest(field=field, wrong=wrong):
                root = self.protocol_six(report((self.error,)))
                root.find("error_summary/" + field).text = wrong
                self.reject(root)

    def test_protocol_six_duplicate_summary_and_fields_fail(self):
        root = self.protocol_six()
        root.append(ET.fromstring(ET.tostring(root.find("error_summary"))))
        self.reject(root)
        root = self.protocol_six(report((self.error,)))
        ET.SubElement(root.find("error_summary"), "errors").text = "100"
        self.reject(root)

    def test_protocol_six_missing_unknown_and_malformed_fields_fail(self):
        for field in ("errors", "error_contexts", "suppressed", "suppressed_contexts"):
            with self.subTest(missing=field):
                root = self.protocol_six(report((self.error,)))
                root.find("error_summary").remove(root.find("error_summary/" + field))
                self.reject(root)
            for malformed in ("-1", "+100", "100.0", "1e2", "١٠٠", "", "000"):
                with self.subTest(field=field, malformed=malformed):
                    root = self.protocol_six(report((self.error,)))
                    root.find("error_summary/" + field).text = malformed
                    self.reject(root)
        root = self.protocol_six(report((self.error,)))
        root.find("error_summary/suppressed_contexts").tag = "unknown"
        self.reject(root)
        root = self.protocol_six(report((self.error,)))
        ET.SubElement(root.find("error_summary/errors"), "nested").text = "100"
        self.reject(root)

    def test_protocol_six_accounting_multiple_contexts(self):
        errors = [error_record(name, site, unique=hex(i + 1)) for i, (name, site) in enumerate(self.sites.items())]
        root = self.protocol_six(report(errors))
        self.assertEqual(root.findtext("error_summary/errors"), "500")
        self.assertEqual(root.findtext("error_summary/error_contexts"), "5")
        self.check(root)

    def test_protocol_tool_and_version_fails(self):
        for field, value in (("protocoltool", "callgrind"), ("protocolversion", "3")):
            with self.subTest(field=field):
                root = report()
                root.find(field).text = value
                self.reject(root)

    def test_unfinished_and_fatal_reports_fail(self):
        root = report()
        root.findall("status")[-1].find("state").text = "RUNNING"
        self.reject(root)
        root = report()
        ET.SubElement(root, "fatal_signal")
        self.reject(root)

    def test_suppression_used_fails(self):
        pair = ET.SubElement(self.root.find("suppcounts"), "pair")
        ET.SubElement(pair, "count").text = "1"
        self.reject()

    def test_missing_or_duplicate_fields_fail(self):
        for field in ("protocoltool", "suppcounts", "errorcounts"):
            with self.subTest(field=field):
                root = report()
                root.remove(root.find(field))
                self.reject(root)
        ET.SubElement(self.root, "protocoltool").text = "memcheck"
        self.reject()

    def test_error_count_mismatch_fails(self):
        self.root.find("errorcounts/pair/unique").text = "0xff"
        self.reject()

    def test_truncated_or_malformed_xml_fails(self):
        for text in ("", "<valgrindoutput>", "<valgrindoutput></wrong>", '<!DOCTYPE x><valgrindoutput/>'):
            with self.subTest(text=text), self.assertRaises(gate.CheckFailure):
                gate.check(text, self.assembly, BINARY, "hardened")

    def test_negative_control_detected_in_both_modes(self):
        negative = error_record("ct_negative_branch", 0x404000, "UninitCondition", "0x2")
        self.check(report((self.error, negative)), negative=True)
        self.check(report((negative,)), self.plain, "plain", True)

    def test_negative_control_missing_fails(self):
        self.reject(negative=True)
        self.reject(report(), self.plain, "plain", True)

    def test_negative_control_cannot_hide_other_conditions(self):
        good = error_record("ct_negative_branch", 0x404000, "UninitCondition", "0x2")
        bad = error_record(gate.WRAPPERS[0], self.sites[gate.WRAPPERS[0]], "UninitCondition", "0x3")
        self.reject(report((good, bad)), negative=True)

    def test_negative_origin_wrong_function_binary_or_description_fails(self):
        for field, value in (("fn", "other_client_request"), ("obj", "/tmp/other")):
            with self.subTest(field=field):
                negative = error_record("ct_negative_branch", 0x404000, "UninitCondition")
                negative.findall("stack")[1].find("frame/" + field).text = value
                self.reject(report((negative,)), negative=True)
        negative = error_record("ct_negative_branch", 0x404000, "UninitCondition")
        negative.find("auxwhat").text = "Uninitialised value was created by a heap allocation"
        self.reject(report((negative,)), negative=True)

    def test_negative_duplicate_primary_and_origin_stacks_fail(self):
        for before_origin in (True, False):
            with self.subTest(before_origin=before_origin):
                negative = error_record("ct_negative_branch", 0x404000, "UninitCondition")
                extra = ET.fromstring(ET.tostring(negative.findall("stack")[0 if before_origin else 1]))
                if before_origin:
                    negative.insert(list(negative).index(negative.find("auxwhat")), extra)
                else:
                    negative.append(extra)
                self.reject(report((negative,)), negative=True)

    def test_negative_missing_origin_or_aux_and_reordered_details_fail(self):
        for target in ("origin", "aux", "reorder"):
            with self.subTest(target=target):
                negative = error_record("ct_negative_branch", 0x404000, "UninitCondition")
                if target == "origin":
                    negative.remove(negative.findall("stack")[1])
                elif target == "aux":
                    negative.remove(negative.find("auxwhat"))
                else:
                    aux = negative.find("auxwhat")
                    negative.remove(aux)
                    negative.append(aux)
                self.reject(report((negative,)), negative=True)

    def test_negative_control_wrong_kind_or_binary_fails(self):
        for kind, obj in (("UninitValue", str(BINARY)), ("UninitCondition", "/tmp/wrong")):
            with self.subTest(kind=kind, obj=obj):
                negative = error_record("ct_negative_branch", 0x404000, kind)
                negative.find("stack/frame/obj").text = obj
                self.reject(report((negative,)), negative=True)

    def test_non_elf_pie_wrong_arch_and_missing_binary_fail(self):
        for header in (b"not-elf", ELF_HEADER[:16] + b"\x03\x00" + ELF_HEADER[18:],
                       ELF_HEADER[:18] + b"\xb7\x00" + ELF_HEADER[20:]):
            with self.subTest(header=header):
                BINARY.write_bytes(header)
                try:
                    self.reject()
                finally:
                    BINARY.write_bytes(ELF_HEADER)
        BINARY.unlink()
        try:
            self.reject()
        finally:
            BINARY.write_bytes(ELF_HEADER)

    def test_cli_accepts_complete_scoped_report(self):
        with tempfile.TemporaryDirectory() as directory:
            xml = Path(directory) / "report.xml"
            disassembly = Path(directory) / "disassembly.txt"
            xml.write_text(ET.tostring(self.root, encoding="unicode"))
            disassembly.write_text(self.assembly)
            command = [sys.executable, str(Path(__file__).with_name("ct-valgrind.py")),
                       "--xml", str(xml), "--disassembly", str(disassembly),
                       "--binary", str(BINARY), "--mode", "hardened"]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("verified strub zero-store", result.stdout)
            self.assertIn("no unexpected errors", result.stdout)

    def test_missing_input_cli_fails(self):
        command = [sys.executable, str(Path(__file__).with_name("ct-valgrind.py")), "--xml", "/nonexistent.xml",
                   "--disassembly", "/nonexistent.asm", "--binary", str(BINARY), "--mode", "plain"]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Memcheck gate failed", result.stderr)


if __name__ == "__main__":
    unittest.main()
