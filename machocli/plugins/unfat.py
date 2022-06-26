#! /usr/bin/env python
import lief
from machocli.plugins.base import Plugin


class PluginUnfat(Plugin):
    name = "unfat"
    description = "Extract binaries from a Mach-o flat binary"

    def add_arguments(self, parser):
        self.parser = parser

    def run(self, args, binary, data):
        if isinstance(binary, lief.MachO.FatBinary):
            for c in binary:
                fname = args.MACHOFILE + "_" + c.header.cpu_type.name
                c.write(fname)
                print("{} extracted".format(fname))
        else:
            print("Not a fat binary!")
