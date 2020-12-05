#! /usr/bin/env python
import hashlib
import lief
from machocli.lib.symhash import symhash
from machocli.plugins.base import Plugin


class PluginInfo(Plugin):
    name = "info"
    description = "Extract info from the MACH-O file"

    def add_arguments(self, parser):
        parser.add_argument('--json', '-j', action='store_true', help='Show everything in JSON format')
        #parser.add_argument('--imports', '-i',  action='store_true', help='Display imports only')
        #parser.add_argument('--exports', '-e',  action='store_true', help='Display exports only')
        #parser.add_argument('--resources', '-r',  action='store_true', help='Display resources only')
        #parser.add_argument('--full', '-f',  action='store_true', help='Full dump of all pefile infos')
        self.parser = parser


    def display_ar(self, flags):
        """
        Show access rights of a section
        """
        res = ""
        if (flags & 0x1) == 1:
            res += "R"
        else:
            res += "-"
        if (flags & 0x2) == 2:
            res += "W"
        else:
            res += "-"
        if (flags & 0x4) == 4:
            res += "X"
        else:
            res += "-"
        return res

    def find_section(self, binary, addr):
        for s in binary.sections:
            if addr >= s.virtual_address and addr <= (s.virtual_address + s.size):
                return s

    def display_hashes(self, data):
        """Display md5, sha1 and sh256 of the data given"""
        for algo in ["md5", "sha1", "sha256"]:
            m = getattr(hashlib, algo)()
            m.update(data)
            print("%-15s %s" % (algo.upper()+":", m.hexdigest()))

    def display_macho(self, binary):
        """
        Display all the information on a Macho file
        """
        sh = symhash(binary)
        print("{:15} {}".format("Symhash:", sh))
        print("{:15} {}".format("Type:", binary.header.cpu_type.name))
        try:
            s = self.find_section(binary, binary.entrypoint)
            if s:
                print("Entry point:\t0x{:x} (Section {})".format(binary.entrypoint, s.name))
            else:
                print("Entry point:\t0x{:x} (Unknown section)".format(binary.entrypoint))
        except lief.not_found:
            pass
        try:
            if binary.code_signature:
                print("Has a signature")
        except lief.not_found:
            pass
        print("")

        # Commands
        print("Commands")
        print("=" * 80)
        for c in binary.commands:
            if c.command.name in ("SEGMENT_64", "SEGMENT"):
                print("{:20} {:10} {:5} {:14} {}".format(
                    c.command.name,
                    c.name if hasattr(c, 'name') else '',
                    c.size,
                    hex(c.virtual_address) if hasattr(c, 'virtual_address') else "",
                    hex(c.file_offset) if hasattr(c, 'file_offset') else "",
                    ))
            elif c.command.name in ["LOAD_DYLIB", "LOAD_WEAK_DYLIB"]:
                print("{:20} {} (version {})".format(
                    c.command.name,
                    c.name,
                    ".".join([str(a) for a in c.current_version])
                ))
            elif c.command.name == "UUID":
                print("{:20} {}".format(
                    c.command.name,
                    ''.join('{:02x}'.format(x) for x in c.uuid)
                ))
            else:
                print("{:20} {:20}".format(
                    c.command.name,
                    c.name if hasattr(c, 'name') else ''
                ))
        print("")

        # Sections
        print("Sections")
        print("=" * 80)
        segments = set([s.segment for s in binary.sections])
        for seg in segments:
            print("="*10 + " {} ({} - {})".format(
                seg.name,
                self.display_ar(seg.init_protection),
                self.display_ar(seg.max_protection),
            ))
            print("{:16} {:12} {:9} {:9} {:25} {}".format( "Name", "VirtAddr", "RawAddr", "Size", "type", "Md5"))
            for s in binary.sections:
                if s.segment == seg:
                    m = hashlib.md5()
                    m.update(bytearray(s.content))
                    print("{:16} {:12} {:9} {:<9} {:25} {}".format(
                        s.name,
                        hex(s.virtual_address),
                        hex(s.offset),
                        s.size,
                        str(s.type).replace("SECTION_TYPES.", ""),
                        m.hexdigest()
                    ))
            print("")

        # Imports (binding infos)
        print("Imports")
        print("=" * 80)
        for f in binary.imported_symbols:
            try:
                print("{:35s} {}".format(f.name, f.binding_info.library.name))
            except lief.not_found:
                print(f.name)

        # Exports
        if len(binary.exported_functions) > 0:
            print("")
            print("Exports")
            print("=" * 80)
            for f in binary.exported_functions:
                print(f.name)


    def run(self, args, binary, data):
        # TODO: test if FAT binary
        if isinstance(binary, lief.MachO.FatBinary):
            if args.json:
                res = "{"
                for c in binary:
                    if len(res) > 1:
                        res += ","
                    res += '"{}":{}'.format(c.header.cpu_type.name, lief.to_json(c))
                res += "}"
                print(res)
            else:
                # Fat binary
                print("Fat binary")
                print("=" * 80)
                print("This binary is a fat-binary containing {} binaries : {}".format(
                    binary.size,
                    ' '.join([a.header.cpu_type.name for a in binary])
                    ))
                self.display_hashes(data)
                print("")
                for c in binary:
                    print(c.header.cpu_type.name)
                    print("="*80)
                    self.display_macho(c)
                    print("")
        else:
            if args.json:
                print(lief.to_json(binary))
            else:
                print("General Information")
                print("=" * 80)
                self.display_hashes(data)
                print("{:15} {} bytes".format("Size:", len(data)))
                self.display_macho(binary)



