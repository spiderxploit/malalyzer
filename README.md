# MALALYZER

Malware Analysis Toolkit — Reverse engineering utility for malware analysts.

## Features

| Command | Description |
|---|---|
| `pe` | Parse PE structure (headers, sections, imports, exports, anomaly scan) |
| `elf` | Parse ELF structure (headers, segments, sections, symbol tables) |
| `dump` | Dump process memory regions with entropy analysis |
| `strings` | Extract ASCII/wide strings with Shannon entropy filter |
| `hash` | Compute MD5, SHA1, SHA256, and file entropy |
| `hooks` | Detect IAT and inline API hooks in PE files |
| `yara` | Scan files with YARA rules (requires libyara-dev) |
| `decode` | Decode shellcode — single/multi-byte XOR, ROL/ROR, ADD/SUB |
| `xorsearch` | Detect XOR keys via Hamming distance and frequency analysis |

## Installation

```bash
git clone https://github.com/spiderxploit/malalyzer
```

## Setup

```bash
cd malalyzer
```

## Compilation

```bash
gcc -O2 -Wall -Wextra -o malalyzer malalyzer.c -lcrypto -lm
```

With YARA support:

```bash
gcc -O2 -Wall -Wextra -o malalyzer malalyzer.c -lcrypto -lm -lyara -DYARA_ENABLED
```

## Usage

```bash
./malalyzer -h
```

### Examples

Parse a PE file:

```bash
./malalyzer pe sample.exe
```

Extract high-entropy strings:

```bash
./malalyzer strings -e 5.5 sample.bin
```

Compute file hashes:

```bash
./malalyzer hash malware.exe
```

Decode shellcode:

```bash
./malalyzer decode shellcode.bin
```

Search XOR-encoded content:

```bash
./malalyzer xorsearch -k 4 encrypted.bin
```

Dump process memory:

```bash
./malalyzer dump 1337
```

Detect API hooks:

```bash
./malalyzer hooks sample.exe
```

## Dependencies

- **OpenSSL** (`libcrypto`) — required for hashing
- **YARA** (`libyara-dev`) — optional, for YARA scanning
- **math library** (`-lm`) — for entropy calculations

## License

MIT
