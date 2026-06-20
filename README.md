<div align="center">

<img width="909" height="142" alt="ascii-art-text(1)" src="https://github.com/user-attachments/assets/1d43a833-afc9-4451-8bc3-43575699e916" />

**A CLI tool to enumerate endpoints on Tor hidden services**

![C++](https://img.shields.io/badge/C%2B%2B-17-blue?style=flat-square&logo=c%2B%2B)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?style=flat-square&logo=linux)
![Tor](https://img.shields.io/badge/requires-Tor-purple?style=flat-square)

*by ocekico — part of the [TorRecon](https://github.com/ocekico) suite*

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Tor Setup](#tor-setup)
- [Usage](#usage)
- [Options](#options)
- [Examples](#examples)
- [Architecture](#architecture)
- [Disclaimer](#disclaimer)

---

## Overview

**TorBuster** is a fast, multithreaded endpoint enumeration tool built specifically for `.onion` hidden services on the Tor network. Every connection is tunneled through Tor's SOCKS5 proxy (`127.0.0.1:9050`), keeping you anonymous throughout the scan.

It supports SSL-over-Tor, automatic circuit rotation on failure, exponential backoff retry logic, rate limiting, HTTP code filtering, redirect following, and file extension appending — giving you a complete directory-busting solution for `.onion` targets.

<img width="1851" height="297" alt="torbuster_screen" src="https://github.com/user-attachments/assets/9b3c1318-0eb9-48e3-98bb-9bf076c2466d" />

---

## Features

| Feature | Description |
|---|---|
| 🔒 **SOCKS5 Tunneling** | All traffic is routed through Tor (`127.0.0.1:9050`) |
| 🔐 **SSL/TLS Support** | Full HTTPS support for `.onion` domains via SSL-over-Tor |
| ⚡ **Multithreading** | Configurable parallel threads for faster scans |
| 🔄 **Circuit Rotation** | Automatic `SIGNAL NEWNYM` on connection failure |
| 📈 **Exponential Backoff** | Smart retry logic with configurable delays |
| 🚦 **Rate Limiting** | Fine-grained request throttling (req/s) |
| 🎯 **HTTP Filtering** | Include or exclude results by HTTP status code |
| ↪️ **Redirect Following** | Tracks 3xx chains up to N hops |
| 🔤 **Extension Appending** | Automatically appends file extensions to wordlist entries |
| 📊 **Scan Summary** | Post-scan report with per-status-class breakdown |
| 🎨 **Colored Output** | Color-coded results by HTTP response class |

---

## Requirements

### System

- Linux (tested on Kali Linux / Debian-based distros & Arch Linux)
- Tor daemon running on port `9050`
- Tor Control Port enabled on port `9051`
- A terminal with UTF-8 and 24-bit ANSI color support

### Libraries

| Library | Purpose |
|---|---|
| `Boost.Asio` | Async I/O and networking |
| `Boost.Beast` | HTTP/1.1 client |
| `OpenSSL` | TLS/SSL support |
| `Boost.System` | Error codes |
| `pthread` | Multithreading |

Install on Debian/Ubuntu/Kali:

```bash
sudo apt install libboost-all-dev libssl-dev build-essential
```

Install on ArchLinux/BlackArch:

```bash
sudo pacman -S boost base-devel
```

---

## Installation

```bash
git clone https://github.com/ocekico/TorBuster.git
cd TorBuster
make
```

The compiled binary will be placed in the project build directory as `torbuster`.
The binary will then be copied to `$(HOME)/.local/bin`.

---

## Tor Setup

TorBuster requires Tor to be running with the Control Port enabled.

**1. Edit your Tor configuration:**

```
# /etc/tor/torrc

SocksPort 9050
ControlPort 9051
CookieAuthentication 1
```

**2. Restart Tor:**

```bash
sudo systemctl restart tor
```

**3. Retrieve the authentication cookie:**

With Debian/Kali Linux:

```bash
cat /run/tor/control.authcookie | xxd -p | tr -d '\n'
```

With Arch Linux:

```bash
sudo cat /var/lib/tor/control_auth_cookie | xxd -p | tr -d '\n'
```

Pass this value to TorBuster with the `-a` flag.

---

## Usage

```
torbuster -u <onion_url> -w <wordlist> [options]
```

---

## Options

### Required

| Flag | Long form | Description |
|---|---|---|
| `-u` | `--url` | Target `.onion` domain |
| `-w` | `--wordlist` | Path to the wordlist file |

### Connection

| Flag | Long form | Description |
|---|---|---|
| `-p` | `--port` | Target port (default: `80`, auto `443` with `-s`) |
| `-a` | `--auth-cookie` | Tor controller authentication cookie |
| `-s` | `--ssl-on-tor` | Enable TLS — for HTTPS `.onion` domains |
| `-R` | `--max-retries` | Max connection retries (default: `3`) |

### Performance

| Flag | Long form | Description |
|---|---|---|
| `-t` | `--threads-max` | Number of parallel threads (default: `1`) |
| `-r` | `--rate-limit-max` | Rate limit in requests/second |

### Filtering

| Flag | Long form | Description |
|---|---|---|
| `-e` | `--exclude-http-code` | Comma-separated HTTP codes to **exclude** |
| `-i` | `--include-http-code` | Comma-separated HTTP codes to **include only** |

### Miscellaneous

| Flag | Long form | Description |
|---|---|---|
| `-L` | `--follow-redirects` | Follow HTTP 3xx redirects (up to 5 hops) |
| `-x` | `--extensions` | Comma-separated extensions to append to each wordlist entry |
| `-v` | `--verbose` | Print debug information |
| `-V` | `--version` | Print version and exit |
| `-h` | `--help` | Show the help menu |

---

## Important
An environment variable 'COOKIE_AUTH' will be created when the option `-a, --auth-cookie` is used for the first time,
this environment variable is necessary in order to perform circuit rotation. You can also create the environment variable
using ```bash export COOKIE_AUTH=<cookie value or password>``` then execute **torbuster**.

## Examples

**Basic scan:**
```bash
./torbuster -u example3g2uuwf6p.onion -w wordlist.txt 
```

**HTTPS target, 4 threads, hide 404s:**
```bash
./torbuster -u example3g2uuwf6p.onion -w wordlist.txt -s -t 4 -e 404
```

**Only show 200 responses, scan for PHP and HTML files:**
```bash
./torbuster -u example3g2uuwf6p.onion -w wordlist.txt -i 200 -x .php,.html
```

**Follow redirects on a custom port:**
```bash
./torbuster -u example3g2uuwf6p.onion -w wordlist.txt -p 8080 -L
```

**Full scan with circuit rotation, rate limiting and retries:**
```bash
./torbuster -u example3g2uuwf6p.onion -w wordlist.txt \
  -t 8 -R 5 -r 10 \
  -a <cookie_value or password>
```

---

## Architecture

TorBuster is composed of four modules:

```
┌──────────────────────────────────────────────────┐
│                    main2.cc                      │
│        CLI parsing · thread orchestration        │
└───────────────────────┬──────────────────────────┘
                        │
          ┌─────────────▼─────────────┐
          │      endpoint_scanner     │
          │  Wordlist · dispatching   │
          │  rate-limit · output      │
          └─────────────┬─────────────┘
                        │
          ┌─────────────▼─────────────┐
          │        tor_client         │
          │  SOCKS5 · SSL · retry     │
          │  reconnect · I/O          │
          └─────────────┬─────────────┘
                        │
          ┌─────────────▼─────────────┐
          │      tor_controller       │
          │  Control port · NEWNYM    │
          │  circuit rotation         │
          └───────────────────────────┘
```

| File | Role |
|---|---|
| `main2.cc` | Entry point — parses CLI arguments and launches scan threads |
| `endpoint_scanner.cc` | Manages the wordlist, splits work across threads, formats and filters output |
| `tor_client.cc` | Manages the SOCKS5 tunnel, SSL streams, retry/backoff, and HTTP I/O |
| `tor_controller.hpp` | (Header-Only) Interfaces with the Tor Control Port to rotate circuits on demand |

---

## Disclaimer

TorBuster is intended **strictly for authorized security testing, research, and educational purposes**.

> Scanning or probing `.onion` services without explicit permission from their operators is **illegal** and **unethical**. The author assumes no responsibility for any misuse of this software. Always obtain proper written authorization before conducting any enumeration or penetration testing activity.

---

Thanks to <a href=https://github.com/sehe>sehe</a> and <a href=https://github.com/bvcxza>bvcxza</a> for creating the SOCKS4/SOCKS5 library used in this project: <a href=https://github.com/sehe/asio-socks45-client>asio-socks45-client</a>
