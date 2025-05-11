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

Installation via `pip` from GitHub or PyPI:

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

![index_video](https://raw.githubusercontent.com/MatrixEditor/dementor/refs/heads/master/docs/source/_static/images/index-video.gif)


## You need more?

Take a look at the [Documentation on GitHub-Pages](https://matrixeditor.github.io/dementor/)


## License

Distributed under the MIT License. See LICENSE for more information.