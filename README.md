# machocli

Python tool to analyse Mach-o files for malware analysis, based on [LIEF](https://lief.quarkslab.com/).

## Usage

```
usage: machocli [-h] {cert,crypto,info,shell,unfat} ...

positional arguments:
  {cert,crypto,info,shell,unfat}
                        Plugins
    cert                Parse certificates from the binary
    crypto              Identifies cryptographic values
    info                Extract info from the MACH-O file
    shell               Launch ipython shell to analyze the Macho file
    unfat               Extract binaries from a Mach-o flat binary

optional arguments:
  -h, --help            show this help message and exit
```

## Alternatives

* [macholibre](https://github.com/aaronst/macholibre)

## LICENSE

This code is provided under [MIT](LICENCE) license.
