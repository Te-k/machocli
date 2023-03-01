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
            i = 0
            for c in binary:
                fname = args.MACHOFILE + "_" + c.header.cpu_type.name + "_" + str(i)
                c.write(fname)
                print("{} extracted".format(fname))
                i += 1
        else:
            print("Not a fat binary!")
