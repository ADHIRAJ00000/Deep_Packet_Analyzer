# DPI Engine — Multi-Threaded Deep Packet Inspection & Traffic Classification System

[![C++](https://img.shields.io/badge/C%2B%2B-17-00599C?style=flat&logo=c%2B%2B&logoColor=white)](https://isocpp.org/)
[![Build](https://img.shields.io/badge/build-passing-brightgreen)](#build--installation)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey)](#build--installation)

A high-performance **Deep Packet Inspection (DPI)** engine written in modern C++17 that parses raw network captures, classifies traffic by application using **TLS SNI / HTTP Host extraction**, and enforces configurable blocking policies — all without relying on any third-party packet-processing library.

The project ships with two implementations: a single-threaded reference engine for clarity, and a **multi-threaded, pipelined architecture** (Reader → Load Balancers → Fast Path workers → Output Writer) using consistent hashing and lock-based concurrent queues to scale packet classification across cores.

---

## Table of Contents

- [Highlights](#highlights)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Core Features](#core-features)
- [Project Structure](#project-structure)
- [Build & Installation](#build--installation)
- [Usage](#usage)
- [Sample Output](#sample-output)
- [Design Decisions](#design-decisions)
- [Roadmap](#roadmap)
- [Skills Demonstrated](#skills-demonstrated)
- [License](#license)

---

## Highlights

- 🧵 **Multi-threaded pipeline architecture** — Reader / Load Balancer / Fast Path / Writer stages communicating via thread-safe, condition-variable-backed queues
- 🔀 **Consistent hashing on the 5-tuple** ensures flow affinity: every packet of a connection is routed to the same worker thread for correct, race-free stateful tracking
- 🔍 **Protocol parsing from raw bytes** — hand-rolled Ethernet / IPv4 / TCP / UDP header parsers with correct network-byte-order handling (`ntohs`/`ntohl`)
- 🔐 **TLS Client Hello & SNI extraction** — parses the TLS handshake to recover the destination hostname from encrypted HTTPS sessions, plus HTTP `Host:` header extraction for plaintext traffic
- 🛡️ **Stateful, flow-based policy engine** — supports IP-based, application-based, and domain-based (substring) blocking rules, applied consistently across an entire connection lifecycle
- 📊 **Real-time traffic classification reporting** — per-application breakdown, thread utilization stats, and forwarded/dropped packet accounting
- ⚙️ **Zero external dependencies** — built entirely on the C++ standard library and POSIX threads; compiles with a single `g++` invocation

---

## Architecture

```
                              ┌──────────────────┐
                              │   Reader Thread   │
                              │  (PCAP ingestion) │
                              └─────────┬──────────┘
                                        │ hash(5-tuple) % N
                          ┌─────────────┴─────────────┐
                          ▼                            ▼
                 ┌─────────────────┐          ┌─────────────────┐
                 │  Load Balancer 0 │          │  Load Balancer 1 │
                 └────────┬─────────┘          └────────┬─────────┘
                          │ hash(5-tuple) % M            │
              ┌───────────┴───────────┐       ┌───────────┴───────────┐
              ▼                       ▼        ▼                       ▼
      ┌───────────────┐       ┌───────────────┐               ┌───────────────┐
      │ Fast Path FP0  │  ...  │ Fast Path FPn  │      ...      │ Fast Path FPk  │
      │ (flow table,   │       │ (flow table,   │               │ (flow table,   │
      │  classification,│       │  classification,│               │  classification,│
      │  policy engine) │       │  policy engine) │               │  policy engine) │
      └────────┬───────┘       └───────┬────────┘               └────────┬───────┘
               └───────────────────────┴────────────────────────────────┘
                                        │
                                        ▼
                             ┌────────────────────┐
                             │  Output Writer       │
                             │  Thread (PCAP)       │
                             └────────────────────┘
```

**Why consistent hashing matters:** because all packets of a single TCP/UDP connection share the same 5-tuple, hashing on that tuple guarantees they're processed by the *same* Fast Path worker in order — which is what makes it safe to maintain per-flow state (SNI, classification, block status) without cross-thread synchronization on the hot path.

---

## Tech Stack

| Category | Technology |
|---|---|
| Language | C++17 |
| Concurrency | `std::thread`, `std::mutex`, `std::condition_variable` |
| Networking | Raw socket-level protocol parsing (Ethernet, IPv4, TCP, UDP, TLS, HTTP) |
| Data format | PCAP (Wireshark-compatible capture format) |
| Build system | g++ / clang++ (CMake-ready) |
| Testing | Python-generated synthetic PCAP fixtures |

---

## Core Features

### 1. Custom Protocol Parser
Parses raw Ethernet, IPv4, TCP, and UDP headers directly from byte buffers with correct big-endian ↔ host byte-order conversion — no `libpcap`/`dpkt` abstraction layer required.

### 2. TLS SNI & HTTP Host Extraction
Walks the TLS Client Hello handshake structure (record header → handshake header → session ID → cipher suites → compression methods → extensions) to locate and decode the **Server Name Indication (SNI)** extension, recovering the plaintext destination hostname even from otherwise encrypted HTTPS sessions. Falls back to HTTP `Host:` header parsing for unencrypted traffic.

### 3. Flow / Connection Tracking
Maintains a 5-tuple-keyed flow table (`{src_ip, dst_ip, src_port, dst_port, protocol} → Flow`) so that classification and blocking decisions persist correctly across every packet in a connection's lifetime.

### 4. Configurable Policy Engine
Supports three rule types, evaluated per-flow:
- **IP-based** — block all traffic from a given source address
- **Application-based** — block by classified app (e.g., YouTube, TikTok, Facebook)
- **Domain-based** — substring match against extracted SNI/Host

### 5. Concurrent Pipeline Engine
A lock-based producer/consumer pipeline (Reader → Load Balancer(s) → Fast Path worker(s) → Writer) that horizontally scales classification throughput across configurable thread pools.

### 6. Traffic Analytics & Reporting
Generates a structured report covering total/forwarded/dropped packet counts, per-thread work distribution, application breakdown by percentage, and the list of detected domains.

---

## Project Structure

```
packet_analyzer/
├── include/
│   ├── pcap_reader.h          # PCAP file I/O interface
│   ├── packet_parser.h        # L2–L4 protocol parsing interface
│   ├── sni_extractor.h        # TLS/HTTP application-layer inspection
│   ├── types.h                # Core data structures (FiveTuple, Flow, AppType)
│   ├── rule_manager.h         # Blocking policy engine
│   ├── connection_tracker.h   # Flow-table management
│   ├── load_balancer.h        # LB worker thread
│   ├── fast_path.h            # FP worker thread
│   ├── thread_safe_queue.h    # Generic concurrent MPMC queue
│   └── dpi_engine.h           # Top-level orchestrator
│
├── src/
│   ├── pcap_reader.cpp
│   ├── packet_parser.cpp
│   ├── sni_extractor.cpp
│   ├── types.cpp
│   ├── main_working.cpp       # Single-threaded reference implementation
│   └── dpi_mt.cpp             # Multi-threaded production implementation
│
├── generate_test_pcap.py      # Synthetic PCAP fixture generator
├── test_dpi.pcap              # Sample capture (mixed protocol traffic)
└── README.md
```

---

## Build & Installation

### Prerequisites
- Linux or macOS
- C++17-compliant compiler (`g++` or `clang++`)
- No external libraries required

### Single-Threaded Build
```bash
g++ -std=c++17 -O2 -I include -o dpi_simple \
    src/main_working.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

### Multi-Threaded Build
```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/dpi_mt.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

---

## Usage

**Basic classification pass:**
```bash
./dpi_engine test_dpi.pcap output.pcap
```

**With policy enforcement:**
```bash
./dpi_engine test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

**Tuning the thread pool:**
```bash
./dpi_engine input.pcap output.pcap --lbs 4 --fps 4
# 4 Load Balancer threads × 4 Fast Path threads = 16 concurrent workers
```

**Generating test fixtures:**
```bash
python3 generate_test_pcap.py
```

---

## Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                 ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4         ║
╚══════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YouTube
[Rules] Blocked IP: 192.168.1.50

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                              ║
║ Forwarded:                    69      Dropped:              8 ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                       ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6% ##########                     ║
║ Unknown              16  20.8% ####                           ║
║ YouTube               4   5.2% # (BLOCKED)                    ║
║ DNS                   4   5.2% #                               ║
║ Facebook              3   3.9%                                ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Design Decisions

- **Flow-level blocking over packet-level blocking** — because the application identity is only knowable once the TLS Client Hello arrives, the engine forwards the initial handshake packets and retroactively marks a flow as blocked, applying that decision to all subsequent packets. This mirrors how real DPI middleboxes behave.
- **Consistent hashing for worker assignment** — guarantees per-connection ordering and avoids the need for cross-thread locking on flow state, trading a small amount of load-balancing precision for lock-free correctness on the hot path.
- **No external packet-parsing dependency** — parsing Ethernet/IP/TCP/TLS by hand demonstrates low-level protocol and byte-order handling rather than delegating to `libpcap`/`dpkt` abstractions.

---

## Roadmap

- [ ] QUIC / HTTP-3 support (encrypted Initial packet SNI extraction)
- [ ] Bandwidth throttling as an alternative to hard blocking
- [ ] Persistent, file-backed rule sets
- [ ] Live terminal dashboard with per-second statistics
- [ ] Expand application fingerprint database

---

## Skills Demonstrated

`C++17` · `Multithreading & Concurrency` · `Network Programming` · `TCP/IP Protocol Stack` · `TLS/SSL Handshake Parsing` · `Systems Programming` · `Producer-Consumer Design Pattern` · `Lock-Based Synchronization` · `Binary Data Parsing` · `Network Security` · `Performance Optimization` · `Software Architecture`

---

## License

This project is licensed under the [MIT License](LICENSE).
