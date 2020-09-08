#! /usr/bin/env python
import sys
import json
import hashlib
import lief
from machocli.plugins.base import Plugin
from IPython import embed


class PluginShell(Plugin):
    name = "shell"
    description = "Launch ipython shell to analyze the Macho file"

    def add_arguments(self, parser):
        self.parser = parser

    def run(self, args, binary, data):
        embed()
