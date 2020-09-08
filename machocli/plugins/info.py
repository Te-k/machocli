#! /usr/bin/env python
import hashlib
import lief
from machocli.plugins.base import Plugin


class PluginInfo(Plugin):
    name = "info"
    description = "Extract info from the MACH-O file"

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
        print("{:15} {}".format("Type:", binary.header.cpu_type.name))
        print("Entry point:\t0x%x" % binary.entrypoint)
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
            if c.command.name == "SEGMENT_64":
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
        print("%-16s %-9s %-12s %-9s %-9s %-25s %s" % ( "Name", "Segname", "VirtAddr", "RawAddr", "Size", "type", "Md5"))
        for s in binary.sections:
            m = hashlib.md5()
            m.update(bytearray(s.content))
            print("%-16s %-9s %-12s %-9s %-9s %-25s %s" % (
                s.name,
                s.segment.name,
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

    def add_arguments(self, parser):
        parser.add_argument('--json', '-j', action='store_true', help='Show everything in JSON format')
        #parser.add_argument('--imports', '-i',  action='store_true', help='Display imports only')
        #parser.add_argument('--exports', '-e',  action='store_true', help='Display exports only')
        #parser.add_argument('--resources', '-r',  action='store_true', help='Display resources only')
        #parser.add_argument('--full', '-f',  action='store_true', help='Full dump of all pefile infos')
        self.parser = parser

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



