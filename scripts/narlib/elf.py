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
ET_DYN = 3

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
        if len(data) < 52 or not data.startswith(b"\x7fELF"):
            raise ElfError(f"{name}: not an ELF file")
        self.name = name
        self.data = data
        self.is_64 = data[4] == 2
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
            for i in range(self.phnum):
                off = self.phoff + i * self.phentsize
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
            for i in range(self.shnum):
                off = self.shoff + i * self.shentsize
                if off + self.shentsize > len(self.data):
                    break
                if self.is_64:
                    vals = struct.unpack_from(e + "IIQQQQIIQQ",
                                              self.data, off)
                else:
                    vals = struct.unpack_from(e + "IIIIIIIIII",
                                              self.data, off)
                raw.append({"name_off": vals[0], "type": vals[1],
                            "offset": vals[4], "size": vals[5],
                            "link": vals[6], "entsize": vals[9]})
            strtab = b""
            if 0 <= self.shstrndx < len(raw):
                s = raw[self.shstrndx]
                strtab = self.data[s["offset"]:s["offset"] + s["size"]]
            for s in raw:
                s["name"] = _str_at(strtab, s["name_off"])
                out.append(s)
            self._sections = out
        return self._sections

    def _section_data(self, section):
        return self.data[section["offset"]:
                         section["offset"] + section["size"]]

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
            entsize = s["entsize"] or (24 if self.is_64 else 16)
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
                # Note: namesz(4) descsz(4) type(4) name(4) desc…
                if len(blob) >= 20:
                    descsz = struct.unpack_from("<I", blob, 4)[0]
                    desc = blob[16:16 + descsz]
                    build_id = desc.hex()
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
            "jni_exports": [s for s in exports
                            if s.startswith("Java_")
                            or s == "JNI_OnLoad"],
            "register_natives_hint": any(
                s["name"] == "RegisterNatives" for s in dynsyms),
            "section_names": section_names,
        }
