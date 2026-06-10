# Shellcode Research Laboratory (SRL)

A terminal-based **analysis and research framework** in pure C for studying
shellcode, encoding algorithms, entropy, and binary structure. SRL is an
*inspection/transformation* toolkit in the spirit of `binwalk`, `radare2`,
`file`, and `strings` — it operates on files you already have. It does **not**
generate exploits or working payloads.

Tested clean with `gcc -Wall -Wextra -pedantic` (0 warnings) and Valgrind
(0 leaks, 0 errors).

---

## Build & Install

```bash
# Dependencies (Kali / Debian / Ubuntu)
sudo apt install build-essential libssl-dev libncurses-dev zlib1g-dev

make              # build ./srl
make test         # run unit tests (codec round-trips + entropy)
make plugins      # build the example plugin -> plugins/hello.so
sudo make install # install to /usr/bin/srl
make clean
```

Libraries used: `libcrypto` (AES), `ncurses` (visualizer), `zlib`
(compression-ratio metric), `dl` (plugins), `pthread`, `m`.

---

## Usage

```bash
srl                         # interactive menu
srl <command> [args]        # one-shot
srl <command> --help        # per-command help
srl --verbose | --debug     # global logging flags
```

| Command     | Purpose |
|-------------|---------|
| `encode`    | transform a payload through one or more codecs (chaining supported) |
| `decode`    | reverse a codec chain, or auto-detect text layers |
| `entropy`   | Shannon entropy, byte distribution, compression ratio, histogram |
| `inspect`   | detect ELF / PE / raw blob, magic bytes, arch, hexdump, strings |
| `analyze`   | heuristic shellcode profile: NOP sleds, bad chars, opcode freq |
| `benchmark` | compare every codec by speed, output size, and entropy |
| `visualize` | interactive ncurses hex / frequency / entropy views |
| `report`    | emit a txt / md / json / html report |
| `plugin`    | list / run dynamically loaded `.so` plugins |

### Codecs

`xor`, `xorm` (multi-byte), `base64`, `base85` (Ascii85), `hex`, `rot` (ROT13),
`caesar`, `url`, `rc4`, `aes128`, `aes256` (CBC, random IV prepended, key
derived via SHA-256). Keyed codecs take `--key`.

### Examples

```bash
srl encode payload.bin --chain xor,aes256,base64 --key s3cr3t -o out.enc
srl decode out.enc --chain xor,aes256,base64 --key s3cr3t
srl decode something.b64        # auto-detect hex/base64/url layers
srl entropy payload.bin
srl analyze payload.bin --bad 00,0a,0d
srl inspect /bin/ls --strings --hex 256
srl benchmark payload.bin --iter 500
srl report payload.bin --format json
```

---

## Architecture

```
srl <verb> ──► main.c dispatch table ──► cmd_<verb>()  (one per module)
                                              │
                          ┌───────────────────┼────────────────────┐
                       codec.c            common.c              log.c/config.c
                   (codec registry,    (file IO, entropy,     (~/.srl/srl.log,
                    encode/decode fns)   hexdump, timing)       ~/.srl/config.ini)
```

```
src/        main, common utils, logging, config
include/    public headers (common, codec, plugin ABI, log, config, modules)
modules/    codec, encode, decode, entropy, inspect, analyze,
            benchmark, visualize, report, plugin
plugins/    example_plugin.c  (+ built hello.so)
tests/      test_codec.c  +  sample files
```

Adding a codec: implement two `srl_codec_fn` functions and add one row to
`TABLE[]` in `modules/codec.c`. Every module then sees it automatically
(encode/decode/benchmark).

State lives under `~/.srl/`: `srl.log`, `config.ini`, and `plugins/`.

---

## Plugin Guide

Plugins are shared objects loaded with `dlopen()`/`dlsym()`. Each must export a
symbol named `srl_plugin` of type `srl_plugin_t` (see `include/plugin.h`) with
`.abi == SRL_PLUGIN_ABI`.

```c
#include "plugin.h"
#include <stdio.h>

static int run(srl_plugin_ctx_t *ctx) {
    printf("got %zu bytes from %s\n", ctx->data_len,
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
srl plugin list
srl plugin run hello payload.bin
```

The context struct is append-only, so plugins built against an older header
keep working as long as the ABI integer matches.

---

## Scope & Honesty

This repository is a working **core**. Fully implemented and tested: the CLI
dispatcher, interactive menu, all 11 codecs with chaining, decode (explicit +
heuristic auto-detect), entropy, inspect (ELF/PE/raw), analyze, benchmark,
ncurses visualizer, report (4 formats), logging, config, and the dlopen plugin
framework with an example.

Natural next steps if you extend it: a real disassembler backend for `analyze`
(e.g. Capstone) instead of byte heuristics, richer PE/ELF section parsing,
and HTML reports with embedded graphs.
