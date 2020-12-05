#! /usr/bin/env python
import datetime
import yara
import os
import copy
from machocli.plugins.base import Plugin


class PluginCrypto(Plugin):
    name = "crypto"
    description = "Identifies cryptographic values"

    def add_arguments(self, parser):
        self.parser = parser

    def convert_physical_addr(self, binary, addr):
        """
        Convert a physical address into its logical address
        """
        for s in binary.sections:
            if (addr >= s.virtual_address) and (addr <= (s.virtual_address + s.size)):
                vaddr = s.virtual_address + addr - s.offset
                return (s.name, vaddr)
        return (None, None)


    def run(self, args, binary, data):
        crypto_db = os.path.dirname(os.path.realpath(__file__))[:-7] + "data/yara-crypto.yar"
        if not os.path.isfile(crypto_db):
            print("Problem accessing the yara database")
            return

        rules = yara.compile(filepath=crypto_db)
        matches = rules.match(data=data)
        if len(matches) > 0:
            for match in matches:
                paddr = match.strings[0][0]
                section, vaddr = self.convert_physical_addr(binary, paddr)
                if section:
                    print("{} at {} ({} - {})".format(
                        match.rule,
                        hex(paddr),
                        section,
                        hex(vaddr)
                    ))
                else:
                    print("{} at {} (Virtual Address and section not found)".format(match.rule, hex(paddr)))
        else:
            print("No cryptographic data found!")
