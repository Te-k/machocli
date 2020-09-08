#! /usr/bin/env python
import sys
import lief
import json
from machocli.plugins.base import Plugin
from machocli.lib.macho import extract_certificates


class PluginCert(Plugin):
    name = "cert"
    description = "Parse certificates from the binary"

    def add_arguments(self, parser):
        self.parser = parser

    def run(self, args, binary, data):
        if isinstance(binary, lief.MachO.FatBinary):
            print("Fat binary!")
        else:
            certs = extract_certificates(binary, data)
            print(json.dumps(certs, indent=4))
