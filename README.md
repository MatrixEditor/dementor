# Dementor

IPv6/IPv4 LLMNR/NBT-NS/mDNS Poisoner and rogue service provider - you can think if it as Responder 2.0. Get more information
on the [Documentation](https://matrixeditor.github.io/dementor/) page.

### Offers

- No reliance on hardcoded or precomputed packets
- Fine-grained, per-protocol configuration using a modular system (see [Docs - Configuration](https://matrixeditor.github.io/dementor/config/index.html))
- Near-complete protocol parity with Responder (see [Docs - Compatibility](https://matrixeditor.github.io/dementor/compat.html))
- Easy integration of new protocols via the extension system
- A lot of new protocols (e.g. IPP, MySQL, X11, ...)

## Installation

Installation via `pip`/`pipx` from GitHub or PyPI:

```bash
pip install dementor
```

## Usage

Just type in _Dementor_, specify the target interface and you are good to go! It is recommended
to run _Dementor_ with `sudo` as most protocol servers use privileged ports.

```bash
sudo Dementor -I "$INTERFACE_NAME"
```

Let's take a look.

![index_video](./docs/source/_static/images/index-video.gif)


### CLI Options

```
 Usage: Dementor [OPTIONS]

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────╮
│ --interface   -I      NAME        Network interface to use (required for poisoning)              │
│ --analyze     -A                  Only analyze traffic, don't respond to requests                │
│ --config      -c      PATH        Path to a configuration file (otherwise standard path is used) │
│ --option      -O      KEY=VALUE   Add an extra option to the global configuration file.          │
│ --yes,--yolo  -y                  Do not ask before starting attack mode.                        │
│ --target      -t      NAME[,...]  Target host(s) to attack                                       │
│ --ignore      -i      NAME[,...]  Target host(s) to ignore                                       │
│ --quiet       -q                  Don't print banner at startup                                  │
│ --version                         Show Dementor's version number                                 │
│ --ts                              Log timestamps to terminal output too                          │
│ --paths                           Displays the default configuration paths                       │
│ --help                            Show this message and exit.                                    │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
```


## You need more?

Take a look at the [Documentation on GitHub-Pages](https://matrixeditor.github.io/dementor/) or at the [Blog Series](https://matrixeditor.github.io/posts/dementor-part-1/).


## License

Distributed under the MIT License. See LICENSE for more information.

## Disclaimer

**Dementor** is intended only for lawful educational purposes: learning, testing
in your own lab, or assessments on systems where you have explicit written
authorization. You agree not to use this software to access,  damage, interfere
with, or exfiltrate data from systems for which you do not have permission.
We make no promises about safety, completeness, or fitness for any purpose. Use
at your own risk. If you discover a vulnerability, please follow responsible
disclosure by using the private disclosing feature offered by GitHub.