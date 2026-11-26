"""ELF parser primitives for the 2.0 modules.

Parses ELF32/ELF64 (little- and big-endian) headers, program
headers, section headers, the dynamic table, and both symbol
tables — enough for the native intelligence module: imports,
exports, dependencies, build id, JNI surface, and hardening
facts (triage keeps its own smaller posture reader; this is
the full one).
"""
import struct

PT_LOAD, PT_DYNAMIC, PT_GNU_RELRO = 1, 2, 0x6474E552
DT_NEEDED, DT_SONAME, DT_BIND_NOW = 1, 14, 24
DT_FLAGS, DT_FLAGS_1 = 30, 0x6FFFFFFB
DF_BIND_NOW, DF_1_NOW = 0x8, 0x1
SHT_SYMTAB, SHT_DYNSYM, SHT_STRTAB, SHT_DYNAMIC = 2, 11, 3, 6
SHT_RELA, SHT_REL = 4, 9
ET_DYN = 3

# Relocation type names for the common cases, per machine.
# Anything unmapped is reported numerically (type-N) rather
# than named from a guess.
RELOC_NAMES = {
    0x3E: {0: "NONE", 1: "64", 2: "PC32", 4: "PLT32",
           5: "COPY", 6: "GLOB_DAT", 7: "JUMP_SLOT",
           8: "RELATIVE", 37: "IRELATIVE"},          # x86-64
    0x03: {0: "NONE", 1: "32", 2: "PC32", 5: "COPY",
           6: "GLOB_DAT", 7: "JUMP_SLOT", 8: "RELATIVE",
           42: "IRELATIVE"},                          # x86
    0x28: {0: "NONE", 2: "ABS32", 20: "COPY",
           21: "GLOB_DAT", 22: "JUMP_SLOT", 23: "RELATIVE",
           160: "IRELATIVE"},                         # ARM
    0xB7: {257: "ABS64", 1024: "COPY", 1025: "GLOB_DAT",
           1026: "JUMP_SLOT", 1027: "RELATIVE",
           1032: "IRELATIVE"},                        # AArch64
}

MACHINES = {0x28: "ARM", 0xB7: "AArch64", 0x03: "x86",
            0x3E: "x86-64", 0x08: "MIPS", 0xF3: "RISC-V"}


class ElfError(Exception):
    pass


def _str_at(blob, off):
    if off >= len(blob):
        return ""
    end = blob.find(b"\x00", off)
    if end < 0:
        end = len(blob)
    return blob[off:end].decode("utf-8", "replace")


class Elf:
    def __init__(self, data, name="lib.so"):
        # Slice comparison, not startswith: data may be an
        # mmap (narlib.mmapio), which has no startswith.
        if len(data) < 52 or data[:4] != b"\x7fELF":
            raise ElfError(f"{name}: not an ELF file")
        if data[4] not in (1, 2):
            raise ElfError(
                f"{name}: invalid EI_CLASS {data[4]} "
                "(expected 1=32-bit or 2=64-bit)")
        if data[5] not in (1, 2):
            raise ElfError(
                f"{name}: invalid EI_DATA {data[5]} "
                "(expected 1=little-endian or 2=big-endian)")
        self.name = name
        self.data = data
        self.is_64 = data[4] == 2
        # The fixed header is 64 bytes (ELF64) / 52 bytes
        # (ELF32); a shorter buffer would leak a bare
        # struct.error from the unpack below.
        if len(data) < (64 if self.is_64 else 52):
            raise ElfError(
                f"{name}: truncated ELF header "
                f"({len(data)} bytes)")
        self.endian = "<" if data[5] != 2 else ">"
        e = self.endian
        if self.is_64:
            vals = struct.unpack_from(e + "HHIQQQIHHHHHH", data, 16)
        else:
            vals = struct.unpack_from(e + "HHIIIIIHHHHHH", data, 16)
        (self.e_type, self.machine, _ver, _entry, self.phoff,
         self.shoff, _flags, _ehsize, self.phentsize, self.phnum,
         self.shentsize, self.shnum, self.shstrndx) = vals
        self._sections = None
        self._program_headers = None

    @property
    def arch(self):
        return MACHINES.get(self.machine, f"machine-{self.machine:#x}")

    def program_headers(self):
        if self._program_headers is None:
            out = []
            e = self.endian
            # An entry size smaller than the fixed struct
            # would let the unpack read past the checked
            # extent and leak a bare struct.error at EOF
            # (2.6.2 robustness round).
            want = 56 if self.is_64 else 32
            if self.phnum and self.phentsize < want:
                raise ElfError(
                    f"{self.name}: program header entry size "
                    f"{self.phentsize} smaller than the "
                    f"{want}-byte entry struct")
            for i in range(self.phnum):
                off = self.phoff + i * self.phentsize
                if off + self.phentsize > len(self.data):
                    raise ElfError(
                        f"{self.name}: program header {i} at "
                        f"{off:#x} extends past end of file")
                if self.is_64:
                    p_type, _fl, p_off, p_v, _p, filesz, _m, align = \
                        struct.unpack_from(e + "IIQQQQQQ",
                                           self.data, off)
                else:
                    p_type, p_off, p_v, _p, filesz, _m, _fl, align = \
                        struct.unpack_from(e + "IIIIIIII",
                                           self.data, off)
                out.append({"type": p_type, "align": align,
                            "filesz": filesz, "offset": p_off,
                            "vaddr": p_v})
            self._program_headers = out
        return self._program_headers

    def sections(self):
        if self._sections is None:
            out = []
            e = self.endian
            raw = []
            # shoff == 0 means "no section header table"
            # (with shnum == 0, or extended numbering this
            # parser does not decode); never read headers
            # from offset 0, which is the ELF header itself.
            want = 64 if self.is_64 else 40
            if self.shoff and self.shnum and \
                    self.shentsize < want:
                raise ElfError(
                    f"{self.name}: section header entry size "
                    f"{self.shentsize} smaller than the "
                    f"{want}-byte entry struct")
            for i in range(self.shnum if self.shoff else 0):
                off = self.shoff + i * self.shentsize
                if off + self.shentsize > len(self.data):
                    raise ElfError(
                        f"{self.name}: section header {i} at "
                        f"{off:#x} extends past end of file")
                if self.is_64:
                    vals = struct.unpack_from(e + "IIQQQQIIQQ",
                                              self.data, off)
                else:
                    vals = struct.unpack_from(e + "IIIIIIIIII",
                                              self.data, off)
                raw.append({"name_off": vals[0], "type": vals[1],
                            "offset": vals[4], "size": vals[5],
                            "link": vals[6], "entsize": vals[9]})
            # SHN_XINDEX (0xffff) is the extended-index
            # escape (real index in section 0's sh_link);
            # it keeps the old no-string-table behaviour.
            # Any other index outside the table is corrupt.
            if raw and self.shstrndx >= len(raw) \
                    and self.shstrndx != 0xFFFF:
                raise ElfError(
                    f"{self.name}: section name string table "
                    f"index {self.shstrndx} out of range "
                    f"({len(raw)} sections)")
            strtab = b""
            if 0 <= self.shstrndx < len(raw):
                s = raw[self.shstrndx]
                if s["offset"] + s["size"] > len(self.data):
                    raise ElfError(
                        f"{self.name}: section name string "
                        "table declares bytes past the end "
                        "of the file")
                strtab = self.data[s["offset"]:s["offset"] + s["size"]]
            for s in raw:
                s["name"] = _str_at(strtab, s["name_off"])
                out.append(s)
            self._sections = out
        return self._sections

    def _section_data(self, section):
        # Section HEADERS are extent-checked at parse time,
        # but the declared content extent was not: a section
        # claiming more bytes than the file holds silently
        # returned whatever follows it in the file, which
        # the symbol reader then decoded into fabricated
        # symbols (stability audit A-04). NOBITS sections
        # occupy no file bytes by definition.
        if section["type"] == 8:  # SHT_NOBITS
            return b""
        end = section["offset"] + section["size"]
        if end > len(self.data):
            raise ElfError(
                f"{self.name}: section {section.get('name') or '?'} "
                f"declares bytes [{section['offset']}, {end}) "
                f"past the end of the file ({len(self.data)} "
                "bytes)")
        return self.data[section["offset"]:end]

    def _vaddr_to_off(self, vaddr):
        """Map a virtual address to a file offset via PT_LOAD."""
        for ph in self.program_headers():
            if ph["type"] != 1:  # PT_LOAD
                continue
            if ph["vaddr"] <= vaddr < ph["vaddr"] + ph["filesz"]:
                return ph["offset"] + (vaddr - ph["vaddr"])
        return None

    def dynamic_entries(self):
        out = []
        e = self.endian
        entsize = 16 if self.is_64 else 8
        fmt = e + "qQ" if self.is_64 else e + "iI"

        def parse(blob):
            entries = []
            for off in range(0, len(blob) - entsize + 1, entsize):
                tag, val = struct.unpack_from(fmt, blob, off)
                if tag == 0:
                    break
                entries.append((tag, val))
            return entries

        for s in self.sections():
            if s["type"] != SHT_DYNAMIC:
                continue
            out.extend(parse(self._section_data(s)))
        if out:
            return out
        # Fallback: PT_DYNAMIC segment (section-less binaries).
        for ph in self.program_headers():
            if ph["type"] == 2:  # PT_DYNAMIC
                blob = self.data[ph["offset"]:
                                 ph["offset"] + ph["filesz"]]
                out.extend(parse(blob))
        return out

    def _strtab_for(self, symtab_section):
        sections = self.sections()
        link = symtab_section["link"]
        if 0 <= link < len(sections):
            return self._section_data(sections[link])
        return b""

    def _checked_entsize(self, section, minimum, what):
        """The section's entry size, or ElfError when a
        nonzero size is smaller than the fixed entry struct:
        stepping by it would let an unpack read past the
        entry and leak a bare struct.error (2.6.2). A zero
        size means "use the struct size" (the historical
        fallback at every call site)."""
        entsize = section["entsize"]
        if entsize and entsize < minimum:
            raise ElfError(
                f"{self.name}: {what} entry size {entsize} "
                f"smaller than the {minimum}-byte entry "
                f"struct in section {section['name']!r}")
        return entsize or minimum

    def symbols(self, section_type):
        """Symbols from one symbol table (SHT_DYNSYM/SHT_SYMTAB).

        Each: {name, bind, type, defined, value, size}."""
        out = []
        e = self.endian
        for s in self.sections():
            if s["type"] != section_type:
                continue
            strtab = self._strtab_for(s)
            blob = self._section_data(s)
            entsize = self._checked_entsize(
                s, 24 if self.is_64 else 16, "symbol")
            for off in range(0, len(blob) - entsize + 1, entsize):
                if self.is_64:
                    name_off, info, _other, shndx, value, size = \
                        struct.unpack_from(e + "IBBHQQ", blob, off)
                else:
                    name_off, value, size, info, _other, shndx = \
                        struct.unpack_from(e + "IIIBBH", blob, off)
                out.append({
                    "name": _str_at(strtab, name_off),
                    "bind": info >> 4, "type": info & 0xF,
                    "defined": shndx != 0, "value": value,
                    "size": size})
        return out

    def _section_symbol_names(self, symtab_section):
        """Symbol names of one symbol-table section, in
        table order (index 0 is the null symbol)."""
        strtab = self._strtab_for(symtab_section)
        blob = self._section_data(symtab_section)
        e = self.endian
        entsize = self._checked_entsize(
            symtab_section, 24 if self.is_64 else 16, "symbol")
        names = []
        for off in range(0, len(blob) - entsize + 1, entsize):
            if self.is_64:
                name_off = struct.unpack_from(
                    e + "I", blob, off)[0]
            else:
                name_off = struct.unpack_from(
                    e + "I", blob, off)[0]
            names.append(_str_at(strtab, name_off))
        return names

    def relocations(self):
        """Relocation entries from SHT_REL / SHT_RELA
        sections (Evolution Phase 3): [{section, offset,
        type, type_name, symbol_index, symbol}]. Symbol
        names resolve through the relocation section's
        linked symbol table; unmapped type numbers are
        reported numerically."""
        return list(self._iter_relocations())

    def _iter_relocations(self):
        """Yield the relocations() entries one at a time.

        A large library can carry hundreds of thousands
        of relocations; consumers that only count them
        (relocation_summary, hence facts()) must not
        materialize the whole list of dicts to do so."""
        e = self.endian
        sections = self.sections()
        names_by_machine = RELOC_NAMES.get(self.machine, {})
        for s in sections:
            if s["type"] not in (SHT_REL, SHT_RELA):
                continue
            has_addend = s["type"] == SHT_RELA
            blob = self._section_data(s)
            if self.is_64:
                minimum = 24 if has_addend else 16
            else:
                minimum = 12 if has_addend else 8
            entsize = self._checked_entsize(s, minimum,
                                            "relocation")
            sym_names = []
            link = s["link"]
            if 0 <= link < len(sections):
                sym_names = self._section_symbol_names(
                    sections[link])
            for off in range(0, len(blob) - entsize + 1, entsize):
                if self.is_64:
                    r_offset, r_info = struct.unpack_from(
                        e + "QQ", blob, off)
                    sym = r_info >> 32
                    rtype = r_info & 0xFFFFFFFF
                else:
                    r_offset, r_info = struct.unpack_from(
                        e + "II", blob, off)
                    sym = r_info >> 8
                    rtype = r_info & 0xFF
                yield {
                    "section": s["name"], "offset": r_offset,
                    "type": rtype,
                    "type_name": names_by_machine.get(
                        rtype, f"type-{rtype}"),
                    "symbol_index": sym,
                    "symbol": sym_names[sym]
                    if sym < len(sym_names) else None}

    def relocation_summary(self):
        """Counts over relocations(): totals, per-section,
        per-type, and the PLT/GOT subset (.rela.plt/.rel.plt
        entries — the lazy-binding surface). Counted by
        streaming _iter_relocations(), so the summary's
        memory does not grow with the relocation count."""
        by_section = {}
        by_type = {}
        plt_got = 0
        total = 0
        for entry in self._iter_relocations():
            total += 1
            by_section[entry["section"]] = \
                by_section.get(entry["section"], 0) + 1
            by_type[entry["type_name"]] = \
                by_type.get(entry["type_name"], 0) + 1
            if entry["section"] in (".rela.plt", ".rel.plt"):
                plt_got += 1
        return {"total": total, "by_section": by_section,
                "by_type": by_type, "plt_got": plt_got}

    def comment_strings(self):
        """Strings of the .comment section (compiler banners
        the toolchain embedded), or [] when the section is
        absent or stripped."""
        for s in self.sections():
            if s["name"] == ".comment":
                blob = self._section_data(s)
                return [part.decode("utf-8", "replace")
                        for part in blob.split(b"\x00")
                        if part][:16]
        return []

    def compiler_fingerprints(self):
        """.comment-based compiler fingerprints (Evolution
        Phase 3): OBSERVED evidence — the exact banner
        strings the toolchain left in the binary. Nothing
        is claimed when the section is stripped."""
        out = []
        for text in self.comment_strings():
            if "clang version" in text:
                out.append({"tool": "clang", "banner": text,
                            "fact_class": "observed",
                            "source": ".comment section"})
            elif text.startswith("GCC:"):
                out.append({"tool": "gcc", "banner": text,
                            "fact_class": "observed",
                            "source": ".comment section"})
            elif "Android" in text and "clang" in text:
                out.append({"tool": "clang (Android NDK)",
                            "banner": text,
                            "fact_class": "observed",
                            "source": ".comment section"})
        return out

    def facts(self):
        """The full native-intelligence fact set for this ELF."""
        dyn = self.dynamic_entries()
        sections = self.sections()
        section_names = [s["name"] for s in sections]
        strtab = b""
        for s in sections:
            if s["name"] == ".dynstr":
                strtab = self._section_data(s)
        if not strtab:
            # Section-less fallback: DT_STRTAB / DT_STRSZ.
            strtab_addr = strsz = None
            for tag, val in dyn:
                if tag == 5:   # DT_STRTAB
                    strtab_addr = val
                elif tag == 10:  # DT_STRSZ
                    strsz = val
            if strtab_addr is not None:
                off = self._vaddr_to_off(strtab_addr)
                if off is not None:
                    strtab = self.data[off:off + (strsz or 0)]
        needed, soname = [], None
        flags = flags1 = 0
        bind_now = False
        for tag, val in dyn:
            if tag == DT_NEEDED:
                needed.append(_str_at(strtab, val))
            elif tag == DT_SONAME:
                soname = _str_at(strtab, val)
            elif tag == DT_BIND_NOW:
                bind_now = True
            elif tag == DT_FLAGS:
                flags = val
            elif tag == DT_FLAGS_1:
                flags1 = val
        if flags & DF_BIND_NOW or flags1 & DF_1_NOW:
            bind_now = True
        build_id = None
        for s in sections:
            if s["name"] == ".note.gnu.build-id":
                blob = self._section_data(s)
                # Note layout: namesz(4) descsz(4) type(4),
                # then the name padded to 4, then the desc
                # padded to 4 — all in the FILE's endianness.
                # The old parse hard-coded little-endian and
                # a 4-byte name, so big-endian files (and any
                # other name size) produced a wrong build id
                # (stability audit A-05).
                if len(blob) >= 12:
                    e = self.endian
                    namesz, descsz = struct.unpack_from(
                        e + "II", blob, 0)
                    desc_off = 12 + ((namesz + 3) & ~3)
                    if desc_off + descsz <= len(blob):
                        build_id = blob[
                            desc_off:desc_off + descsz].hex()
        dynsyms = self.symbols(SHT_DYNSYM)
        imports = sorted({s["name"] for s in dynsyms
                          if not s["defined"] and s["name"]})
        exports = sorted({s["name"] for s in dynsyms
                          if s["defined"] and s["name"]
                          and s["bind"] in (1, 2)})
        loads = [p for p in self.program_headers()
                 if p["type"] == PT_LOAD]
        aligns = [p["align"] for p in loads]
        return {
            "name": self.name,
            "elf_class": "ELF64" if self.is_64 else "ELF32",
            "arch": self.arch,
            "type": "ET_DYN" if self.e_type == ET_DYN
                    else f"ET_{self.e_type}",
            "soname": soname,
            "needed": needed,
            "build_id": build_id,
            "has_symtab": any(s["type"] == SHT_SYMTAB
                              for s in sections),
            "has_gnu_relro": any(p["type"] == PT_GNU_RELRO
                                 for p in self.program_headers()),
            "bind_now": bind_now,
            "load_align_min": min(aligns) if aligns else None,
            "load_align_max": max(aligns) if aligns else None,
            "aligned_16k": bool(aligns)
            and min(aligns) >= 0x4000,
            "imports": imports,
            "exports": exports,
            # jni_exports is the Java_* export list ONLY
            # (M2-13): JNI_OnLoad is a bridge marker, not a
            # Java_* export, and counting it here inflated
            # every JNI-export count by one against a plain
            # Java_* census. JNI_OnLoad remains visible in
            # the full "exports" list above, which is where
            # bridge classification reads it from.
            "jni_exports": [s for s in exports
                            if s.startswith("Java_")],
            "register_natives_hint": any(
                s["name"] == "RegisterNatives" for s in dynsyms),
            "section_names": section_names,
            "relocations": self.relocation_summary(),
            "comment_strings": self.comment_strings(),
            "compiler_fingerprints": self.compiler_fingerprints(),
        }
