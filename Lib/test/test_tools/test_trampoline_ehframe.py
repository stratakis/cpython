"""Tests for Tools/jit/_trampoline_ehframe.py with synthetic object files.

The generator's output for this build's own trampoline object, and the
runtime that patches it, are tested in test.test_perf_profiler.
"""

import os
import struct
import unittest

from test.support import os_helper
from test.support.script_helper import assert_python_failure, assert_python_ok
from test.test_tools import imports_under_tool, skip_if_missing, toolsdir

skip_if_missing("jit")
with imports_under_tool("jit"):
    import _trampoline_ehframe as ehframe

SCRIPT = os.path.join(toolsdir, "jit", "_trampoline_ehframe.py")
PCREL_SDATA4 = ehframe._DW_EH_PE_pcrel | ehframe._DW_EH_PE_sdata4
PCREL_ABSPTR = ehframe._DW_EH_PE_pcrel | ehframe._DW_EH_PE_absptr


def fake_cie(*, version=1, augmentation=b"zR", ra_column=16,
             encoding=PCREL_SDATA4, cie_id=0, endian="<"):
    """A CIE like the assembler's: code align 1, data align -8, one
    DW_CFA_def_cfa instruction, padded with DW_CFA_nop to 8 bytes."""
    body = bytes([version]) + augmentation + b"\x00"
    body += bytes([1, 0x78, ra_column, 1, encoding])
    body += bytes([0x0C, 7, 8])  # DW_CFA_def_cfa: r7 (rsp) ofs 8
    body += b"\x00" * (-(8 + len(body)) % 8)
    return struct.pack(f"{endian}II", 4 + len(body), cie_id) + body


def fake_fde(cie_total, *, field_size=4, address_range=8,
             instructions=b"\x41\x0e\x10\x86\x02", endian="<"):
    """An FDE right after a CIE of cie_total bytes, padded to 8 bytes."""
    byteorder = "little" if endian == "<" else "big"
    body = struct.pack(f"{endian}I", cie_total + 4)  # CIE pointer, relative to itself
    # initial_location as an assembler would leave it, the parser zeroes it.
    body += (-40).to_bytes(field_size, byteorder, signed=True)
    body += address_range.to_bytes(field_size, byteorder)
    body += b"\x00"  # augmentation data length
    body += instructions
    body += b"\x00" * (-(4 + len(body)) % 8)
    return struct.pack(f"{endian}I", len(body)) + body


def fake_ehframe(text_size=8, *, field_size=4, endian="<"):
    """A CIE and an FDE for text_size bytes of code."""
    encoding = PCREL_SDATA4 if field_size == 4 else PCREL_ABSPTR
    cie = fake_cie(encoding=encoding, endian=endian)
    return cie + fake_fde(len(cie), field_size=field_size,
                          address_range=text_size, endian=endian)


def fake_elf(*, endian="<", e_machine=ehframe._EM_X86_64, text=b"\x55\xc3",
             eh_frame=None, text_type=1, extra_sections=()):
    """A minimal ELF64 relocatable object with .text, .eh_frame and .shstrtab."""
    E = ehframe
    if eh_frame is None:
        eh_frame = fake_ehframe(len(text), endian=endian)
    section_list = [(b".text", text_type, text), (b".eh_frame", 1, eh_frame)]
    section_list += [(name, 1, data) for name, data in extra_sections]
    shstrtab = (b"\x00" + b"".join(name + b"\x00" for name, _, _ in section_list)
                + b".shstrtab\x00")
    section_list.append((b".shstrtab", 3, shstrtab))
    offset = E._ELF64_HEADER_SIZE
    blobs = b""
    headers = [b"\x00" * E._ELF64_SECTION_HEADER_SIZE]  # the null section
    for name, sh_type, data in section_list:
        # Elf64_Shdr: name, type, flags, addr, offset, size, link, info,
        # addralign, entsize.
        headers.append(struct.pack(f"{endian}IIQQQQIIQQ",
                                   shstrtab.index(name + b"\x00"), sh_type,
                                   0, 0, offset, len(data), 0, 0, 1, 0))
        blobs += data
        offset += len(data)
    data_encoding = E._ELFDATA2LSB if endian == "<" else E._ELFDATA2MSB
    ident = b"\x7fELF" + bytes([E._ELFCLASS64, data_encoding, 1, 0]) + bytes(8)
    # Elf64_Ehdr after e_ident: type, machine, version, entry, phoff, shoff,
    # flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx.
    header = ident + struct.pack(f"{endian}HHIQQQIHHHHHH", 1, e_machine, 1, 0, 0,
                                 offset, 0, E._ELF64_HEADER_SIZE, 0, 0,
                                 E._ELF64_SECTION_HEADER_SIZE, len(headers),
                                 len(headers) - 1)
    return header + blobs + b"".join(headers)


def fake_macho(cputype, text, eh_frame, *, text_flags=0):
    """A minimal MH_OBJECT: one __TEXT segment with __text and __eh_frame
    sections, section data right after the load command."""
    E = ehframe
    segment_size = E._MACHO64_SEGMENT_COMMAND_SIZE + 2 * E._MACHO64_SECTION_SIZE
    text_offset = E._MACHO64_HEADER_SIZE + segment_size
    eh_offset = text_offset + len(text)
    sections = b""
    for name, size, offset, flags in (("__text", len(text), text_offset, text_flags),
                                      ("__eh_frame", len(eh_frame), eh_offset, 0)):
        sections += struct.pack("<16s16sQQIIIIIIII", name.encode(), b"__TEXT",
                                0, size, offset, 0, 0, 0, flags, 0, 0, 0)
    segment = struct.pack("<II16sQQQQIIII", E._LC_SEGMENT_64, segment_size,
                          b"__TEXT", 0, len(text) + len(eh_frame), text_offset,
                          len(text) + len(eh_frame), 7, 5, 2, 0)
    header = struct.pack("<IIIIIIII", E._MH_MAGIC_64, cputype, 0, 1, 1,
                         segment_size, 0, 0)
    return header + segment + sections + text + eh_frame


def fake_fat(blobs, *, magic=None):
    """A fat container of (cputype, thin object) pairs."""
    E = ehframe
    if magic is None:
        magic = E._FAT_MAGIC
    if magic == E._FAT_MAGIC:
        entry_format, entry_size = ">IIIII", 20
    else:
        entry_format, entry_size = ">IIQQII", 32
    offset = E._FAT_HEADER_SIZE + entry_size * len(blobs)
    entries = b""
    body = b""
    for cputype, blob in blobs:
        fields = [cputype, 0, offset + len(body), len(blob), 0]
        if entry_size == 32:
            fields.append(0)
        entries += struct.pack(entry_format, *fields)
        body += blob
    return struct.pack(">II", magic, len(blobs)) + entries + body


def load(blob):
    """Run load_object() on an object given as bytes."""
    with os_helper.temp_dir() as tmp:
        path = os.path.join(tmp, "object.o")
        with open(path, "wb") as f:
            f.write(blob)
        return ehframe.load_object(path)


class TestParseEhframe(unittest.TestCase):
    def parse(self, data, text_size=8, endian="<"):
        return ehframe.parse_ehframe(bytes(data), endian, text_size)

    def test_parse(self):
        """Both FDE pointer encodings, in both byte orders."""
        cases = [(PCREL_SDATA4, 4, 8), (PCREL_ABSPTR, 8, 20)]
        for encoding, field_size, text_size in cases:
            for endian in ("<", ">"):
                with self.subTest(encoding=hex(encoding), endian=endian):
                    cie = fake_cie(encoding=encoding, endian=endian)
                    fde = fake_fde(len(cie), field_size=field_size,
                                   address_range=text_size, endian=endian)
                    result = self.parse(cie + fde, text_size, endian)
                    self.assertEqual(result.field_size, field_size)
                    self.assertEqual(result.fde_pc_offset, len(cie) + 8)
                    self.assertEqual(result.fde_range_offset,
                                     len(cie) + 8 + field_size)
                    # Both patchable fields zeroed, everything else untouched.
                    expected = bytearray(cie + fde)
                    start = len(cie) + 8
                    expected[start:start + 2 * field_size] = bytes(2 * field_size)
                    self.assertEqual(result.data, bytes(expected))

    def test_parse_rejects_malformed(self):
        cie = fake_cie()
        fde = fake_fde(len(cie))
        cases = [
            ("version", fake_cie(version=3) + fde, 8),
            ("augmentation", fake_cie(augmentation=b"zPLR") + fde, 8),
            ("encoding", fake_cie(encoding=0x1A) + fde, 8),
            ("exactly one FDE", cie + fde + fde, 8),
            ("address_range", cie + fde, 12),
            ("no FDE", cie, 8),
            ("no CIE", b"", 8),
            ("bad CIE length", b"\xff\xff\xff\xff" + cie[4:] + fde, 8),
            ("empty", cie + fake_fde(len(cie), address_range=0), 0),
            ("larger than",
             cie + fake_fde(len(cie), instructions=b"\x00" * 1100), 8),
        ]
        for message, data, text_size in cases:
            with self.subTest(message):
                with self.assertRaisesRegex(ValueError, message):
                    self.parse(data, text_size)


class TestElfObjects(unittest.TestCase):
    def test_both_byte_orders(self):
        cases = [("<", ehframe._EM_X86_64, "__x86_64__"),
                 (">", ehframe._EM_AARCH64, "__aarch64__")]
        for endian, e_machine, macro in cases:
            with self.subTest(endian=endian):
                (obj,) = load(fake_elf(endian=endian, e_machine=e_machine))
                self.assertEqual(obj.endian, endian)
                self.assertEqual(obj.arch_macro, macro)
                self.assertEqual(obj.sections[".text"], b"\x55\xc3")
                frame = ehframe.build_ehframe(obj)
                cie_size = len(fake_cie(endian=endian))
                self.assertEqual(
                    (frame.fde_pc_offset, frame.fde_range_offset, frame.field_size),
                    (cie_size + 8, cie_size + 12, 4))
                self.assertEqual(frame.data[cie_size + 8:cie_size + 16], bytes(8))

    def test_rejects_malformed(self):
        cases = [
            ("unsupported ELF machine", fake_elf(e_machine=243)),
            ("no contents", fake_elf(text_type=ehframe._SHT_NOBITS)),
            ("more than one .text", fake_elf(extra_sections=((b".text", b"\x90"),))),
            ("truncated ELF header", fake_elf()[:40]),
            ("section headers extend", fake_elf()[:-8]),
            ("not an ELF64", b"\x7fELF\x01" + bytes(59)),
            ("empty", fake_elf(text=b"", eh_frame=fake_ehframe(0))),
        ]
        for message, blob in cases:
            with self.subTest(message):
                with self.assertRaisesRegex(ValueError, message):
                    for obj in load(blob):
                        ehframe.build_ehframe(obj)


class TestMachoObjects(unittest.TestCase):
    X86 = ehframe._CPU_TYPE_X86_64
    ARM64 = ehframe._CPU_TYPE_ARM64

    def test_thin_and_fat(self):
        """Mach-O objects and both fat container formats."""
        x86 = fake_macho(self.X86, b"\x55\xc3", b"x86 eh_frame")
        arm = fake_macho(self.ARM64, b"\xc0\x03\x5f\xd6", b"arm64 eh_frame")
        (thin,) = load(arm)
        self.assertEqual(thin.arch_macro, "__aarch64__")
        self.assertEqual(thin.sections[".text"], b"\xc0\x03\x5f\xd6")
        self.assertEqual(thin.sections[".eh_frame"], b"arm64 eh_frame")
        for magic in (ehframe._FAT_MAGIC, ehframe._FAT_MAGIC_64):
            with self.subTest(magic=hex(magic)):
                fat = fake_fat([(self.X86, x86), (self.ARM64, arm)], magic=magic)
                slices = load(fat)
                self.assertEqual([s.arch_macro for s in slices],
                                 ["__x86_64__", "__aarch64__"])
                self.assertEqual(slices[0].sections[".eh_frame"], b"x86 eh_frame")
                self.assertEqual(slices[1].sections[".text"], b"\xc0\x03\x5f\xd6")

    def test_rejects_malformed(self):
        text, frame = b"\x55\xc3", b"eh_frame"
        good = fake_macho(self.X86, text, frame)
        header_size = ehframe._MACHO64_HEADER_SIZE
        segment_size = ehframe._MACHO64_SEGMENT_COMMAND_SIZE

        def patched(offset, value):
            return good[:offset] + struct.pack("<I", value) + good[offset + 4:]

        cases = [
            ("truncated Mach-O header", good[:16]),
            ("unsupported Mach-O CPU type", fake_macho(7, text, frame)),
            ("load commands extend", patched(20, 0xFFFF)),  # sizeofcmds
            ("bad load command size", patched(header_size + 4, 4)),
            ("section table extends", patched(header_size + 64, 100)),  # nsects
            ("extends past the end",
             patched(header_size + segment_size + 48, len(good))),  # __text offset
            ("no architectures", fake_fat([])),
            ("is truncated", fake_fat([(self.X86, good)])[:-4]),
            ("does not match", fake_fat([(self.ARM64, good)])),
            ("not an ELF64, Mach-O 64 or fat", b"junk" * 4),
        ]
        for section_type in ehframe._ZEROFILL_SECTION_TYPES:
            cases.append(("no contents",
                          fake_macho(self.X86, text, frame, text_flags=section_type)))
        for message, blob in cases:
            with self.subTest(message):
                with self.assertRaisesRegex(ValueError, message):
                    load(blob)


class TestGenerate(unittest.TestCase):
    def write(self, tmp, name, blob):
        path = os.path.join(tmp, name)
        with open(path, "wb") as f:
            f.write(blob)
        return path

    def test_generate_writes_c_source(self):
        with os_helper.temp_dir() as tmp:
            x86 = self.write(tmp, "x86.o", fake_elf())
            arm = self.write(tmp, "arm.o",
                             fake_elf(endian=">", e_machine=ehframe._EM_AARCH64))
            out = os.path.join(tmp, "trampoline_ehframe.c")
            entries = ehframe.generate([x86, arm], out)
            self.assertEqual([obj.arch_macro for obj, _ in entries],
                             ["__x86_64__", "__aarch64__"])
            with open(out) as f:
                source = f.read()
            self.assertIn("#if defined(__aarch64__)", source)
            self.assertIn("#elif defined(__x86_64__)", source)
            self.assertIn("const _PyTrampolineEhFrame _Py_trampoline_ehframe = {",
                          source)
            cie_size = len(fake_cie())
            self.assertIn(f"    {cie_size + 8},  /* fde_pc_offset */", source)
            self.assertIn(f"    {cie_size + 12},  /* fde_range_offset */", source)
            self.assertIn("    4,  /* fde_field_size */", source)
            self.assertFalse(os.path.exists(out + ".tmp"))
            # The output is reproducible.
            ehframe.generate([x86, arm], out + ".again")
            with open(out + ".again") as f:
                self.assertEqual(f.read(), source)

    def test_generate_rejects_duplicate_architecture(self):
        with os_helper.temp_dir() as tmp:
            a = self.write(tmp, "a.o", fake_elf())
            b = self.write(tmp, "b.o", fake_elf())
            out = os.path.join(tmp, "out.c")
            with self.assertRaisesRegex(ValueError, "are both __x86_64__"):
                ehframe.generate([a, b], out)
            self.assertFalse(os.path.exists(out))


class TestCommandLine(unittest.TestCase):
    def test_reports_errors(self):
        with os_helper.temp_dir() as tmp:
            out = os.path.join(tmp, "out.c")
            junk = os.path.join(tmp, "junk.o")
            with open(junk, "wb") as f:
                f.write(b"not an object file")
            missing = os.path.join(tmp, "missing.o")
            rc, _, err = assert_python_failure(SCRIPT, "-o", out, missing)
            self.assertEqual(rc, 1)
            self.assertIn(b"error: ", err)
            rc, _, err = assert_python_failure(SCRIPT, "-o", out, junk)
            self.assertEqual(rc, 1)
            self.assertIn(b"not an ELF64, Mach-O 64 or fat Mach-O object", err)
            self.assertFalse(os.path.exists(out))
            rc, _, _ = assert_python_failure(SCRIPT, junk)  # no -o
            self.assertEqual(rc, 2)

    def test_generates(self):
        with os_helper.temp_dir() as tmp:
            obj = os.path.join(tmp, "x86.o")
            with open(obj, "wb") as f:
                f.write(fake_elf())
            out = os.path.join(tmp, "out.c")
            rc, stdout, _ = assert_python_ok(SCRIPT, "-o", out, obj)
            self.assertIn(b"Generated", stdout)
            self.assertTrue(os.path.exists(out))


if __name__ == "__main__":
    unittest.main()
