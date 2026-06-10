# Shellcode Research Laboratory (SRL)

```
     ____  ____  _
    / ___||  _ \| |       Shellcode Research Laboratory
    \___ \| |_) | |       v1.0  -  research & analysis framework
     ___) |  _ <| |___    Author : TENETx0
    |____/|_| \_\_____|   GitHub : github.com/TENETx0/Shellcode_Research_Laboratory
```

> A terminal-based framework in pure C for **analyzing** shellcode, encodings, entropy, and binary structure.

**Author:** [TENETx0](https://github.com/TENETx0) &nbsp;•&nbsp; **Repo:** [Shellcode_Research_Laboratory](https://github.com/TENETx0/Shellcode_Research_Laboratory)

[![Build](https://img.shields.io/badge/build-passing-brightgreen)](#building)
[![Language](https://img.shields.io/badge/C-C11-blue)](#)
[![Warnings](https://img.shields.io/badge/gcc%20--Wall%20--Wextra%20--pedantic-0%20warnings-success)](#)
[![Valgrind](https://img.shields.io/badge/valgrind-0%20leaks-success)](#)
[![License](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Kali-informational)](#)

SRL is an **inspection and transformation toolkit** in the spirit of `binwalk`,
`radare2`, `file`, and `strings`. It operates on files you already have:
identifying them, measuring their entropy, transforming them through standard
codecs, and reporting on the results.

> ⚠️ **Scope:** SRL is a *research and analysis* tool. It does **not** generate
> exploits, working payloads, or evasion-specialized transforms, and it has no
> network, injection, or execution capability. It reads and analyzes files.

---

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Building](#building)
- [Usage](#usage)
- [Codecs](#codecs)
- [Architecture](#architecture)
- [Plugins](#plugins)
- [Configuration & State](#configuration--state)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## Features

- **Encode / decode** through 11 codecs with arbitrary **chaining** and byte-exact reversal
- **Auto-detection** of stacked text encodings (hex / base64 / url) on decode
- **Entropy analysis** — Shannon entropy, byte-distribution histogram, zlib compression ratio
- **Binary inspector** — ELF / PE / raw detection, magic bytes, architecture, hexdump, strings
- **Shellcode profiler** — NOP-sled detection, bad-character flagging, opcode-frequency stats
- **Benchmark** — compare every codec by speed, output size, and entropy
- **ncurses visualizer** — interactive hex / frequency / sliding-entropy views
- **Reports** — txt / markdown / json / html
- **Plugin framework** — `dlopen`/`dlsym` shared objects with a stable ABI
- **Quality** — builds with `-Wall -Wextra -pedantic` at **0 warnings**, **Valgrind-clean**

---

## Installation

### Dependencies (Kali / Debian / Ubuntu)
```bash
sudo apt update
sudo apt install build-essential libssl-dev libncurses-dev zlib1g-dev
```

### Build & install
```bash
git clone https://github.com/TENETx0/Shellcode_Research_Laboratory.git
cd Shellcode_Research_Laboratory
make            # build ./srl
make test       # run the unit tests
sudo make install   # -> /usr/bin/srl
```

Uninstall with `sudo make uninstall`.

---

## Building

| Target          | Action |
|-----------------|--------|
| `make`          | build the `srl` binary |
| `make test`     | build & run codec/entropy unit tests |
| `make plugins`  | build the example plugin (`plugins/hello.so`) |
| `make install`  | install to `$(PREFIX)/bin` (default `/usr`) |
| `make uninstall`| remove the installed binary |
| `make clean`    | remove objects, binary, test, plugins |

Override the prefix: `make install PREFIX=$HOME/.local`.

Libraries linked: `libcrypto`, `ncurses`, `zlib`, `dl`, `pthread`, `m`.

---

## Usage

```bash
srl                    # interactive menu
srl <command> [args]   # one-shot
srl <command> --help   # detailed per-command help
srl --verbose|--debug  # global logging
```

| Command | Purpose |
|---------|---------|
| `encode`    | transform a payload through codecs (chaining) |
| `decode`    | reverse a chain, or auto-detect text layers |
| `entropy`   | randomness + byte statistics |
| `inspect`   | format detection, magic bytes, hexdump, strings |
| `analyze`   | NOP sleds, bad chars, opcode frequency, arch heuristic |
| `benchmark` | compare codecs by speed/size/entropy |
| `visualize` | interactive ncurses viewer |
| `report`    | emit txt/md/json/html |
| `plugin`    | list / run dynamic plugins |

### Examples
```bash
srl encode payload.bin --chain xor,aes256,base64 --key s3cr3t -o out.enc
srl decode out.enc --chain xor,aes256,base64 --key s3cr3t
srl decode blob.b64                  # auto-detect text layers
srl entropy payload.bin
srl analyze payload.bin --bad 00,0a,0d
srl inspect /bin/ls --strings --hex 256
srl benchmark payload.bin --iter 500
srl report payload.bin --format json
```

---

## Codecs

`xor`, `xorm` (multi-byte), `base64`, `base85` (Ascii85), `hex`, `rot` (ROT13),
`caesar`, `url`, `rc4`, `aes128`, `aes256`.

AES uses OpenSSL EVP in CBC mode with a random IV prepended to the output and a
key derived from the passphrase via SHA-256. Keyed codecs take `--key`.
`rot`/`caesar` transform letters only (other bytes pass through), so they are
not byte-exact on arbitrary binary — by design.

---

## Architecture

```
srl <verb> ─► main.c dispatch table ─► cmd_<verb>()   (one per module)
                                            │
                       ┌────────────────────┼─────────────────────┐
                    codec.c             common.c               log.c/config.c
              (codec registry,      (file IO, entropy,      ~/.srl/srl.log
               encode/decode)        hexdump, timing)        ~/.srl/config.ini
```

```
src/        main, common utils, logging, config
include/    public headers (common, codec, plugin ABI, log, config, modules)
modules/    codec, encode, decode, entropy, inspect, analyze,
            benchmark, visualize, report, plugin
plugins/    example_plugin.c
tests/      test_codec.c + sample files
```

**Add a codec:** implement two `srl_codec_fn` functions and append one row to
`TABLE[]` in `modules/codec.c`. Every module (encode/decode/benchmark) picks it
up automatically.

---

## Plugins

Plugins are shared objects loaded with `dlopen()`/`dlsym()`. Each exports a
symbol `srl_plugin` of type `srl_plugin_t` (see `include/plugin.h`) with
`.abi == SRL_PLUGIN_ABI`.

```c
#include "plugin.h"
#include <stdio.h>

static int run(srl_plugin_ctx_t *ctx) {
    printf("%zu bytes from %s\n", ctx->data_len,
           ctx->input_path ? ctx->input_path : "(none)");
    return 0;
}
srl_plugin_t srl_plugin = {
    .name = "hello", .version = "1.0",
    .description = "demo", .abi = SRL_PLUGIN_ABI, .execute = run,
};
```

```bash
gcc -shared -fPIC -Iinclude plugins/example_plugin.c -o hello.so
cp hello.so ~/.srl/plugins/
srl plugin run hello payload.bin
```

The context struct is append-only, so plugins built against older headers keep
working as long as the ABI integer matches.

---

## Configuration & State

Everything lives under `~/.srl/`:

| File              | Purpose |
|-------------------|---------|
| `config.ini`      | default output path, theme, log level, report format |
| `srl.log`         | command / error / timing log |
| `plugins/*.so`    | installed plugins |

Run `srl` as your normal user (not `sudo`) so state lands in your home dir.

---

## Contributing

Pull requests welcome. Please ensure:
- `make` builds with **0 warnings** under `-Wall -Wextra -pedantic`
- `make test` passes
- New allocations are freed (run under Valgrind: `valgrind --leak-check=full ./srl ...`)

See [CONTRIBUTING.md](CONTRIBUTING.md) and the issue templates.

---

## Roadmap

- [ ] Capstone-backed disassembly in `analyze` (replace byte heuristics)
- [ ] Richer ELF/PE section & import parsing in `inspect`
- [ ] HTML reports with embedded SVG graphs
- [ ] Manifest-based plugin enable/disable registry

---

## License

Apache 2.0

Copyright (c) 2026 TENETx0.

---

## Disclaimer

SRL is provided for **education, research, malware analysis, reverse
engineering, and authorized security testing only**. You are responsible for
complying with all applicable laws and for only analyzing files you are
authorized to handle. The authors accept no liability for misuse.
