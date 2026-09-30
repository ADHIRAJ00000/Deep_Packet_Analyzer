# DPI Engine: Multi-Threaded Deep Packet Inspection in C++17

A deep packet inspection engine written in C++17. It reads a PCAP capture, parses packets from raw bytes, identifies the application behind each connection using the TLS SNI or HTTP Host header, and applies configurable blocking rules. It uses only the C++ standard library and POSIX threads.

There are two implementations in the repo: a single-threaded version that is easy to read, and a multi-threaded pipeline (Reader → Load Balancers → Fast Path workers → Writer) that spreads flows across worker threads.

## Why I built this

I wanted to understand how firewalls and network monitors can tell which app a connection belongs to, even when the traffic is HTTPS. So I wrote the whole pipeline by hand: packet parsing, TLS Client Hello parsing to read the SNI, per-flow state tracking, and a multi-threaded design where each flow is handled by a single worker.

## Architecture

```
                    ┌───────────────────┐
                    │   Reader Thread   │
                    │ (PCAP ingestion)  │
                    └─────────┬─────────┘
                              │ hash(5-tuple) % N
                ┌─────────────┴─────────────┐
                ▼                           ▼
        ┌───────────────┐           ┌───────────────┐
        │ Load Balancer0│           │ Load Balancer1│
        └───────┬───────┘           └───────┬───────┘
                │ hash(5-tuple) % M         │
        ┌───────┴───────┐           ┌───────┴───────┐
        ▼               ▼           ▼               ▼
   ┌─────────┐     ┌─────────┐ ┌─────────┐     ┌─────────┐
   │  FP 0   │ ... │  FP n   │ │  ...    │ ... │  FP k   │
   │ flow table, classification, policy engine (per FP)   │
   └────┬────┘     └────┬────┘ └────┬────┘     └────┬────┘
        └───────────────┴───────────┴───────────────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │   Output Writer   │
                    │   Thread (PCAP)   │
                    └───────────────────┘
```

**Flow affinity:** all packets of one TCP/UDP connection share the same 5-tuple, so hashing on it sends them to the same Fast Path worker, in order. Because a flow's state (SNI, app type, blocked or not) lives inside one worker only, the flow table itself needs no locks. The threads talk to each other through queues built on `std::mutex` and `std::condition_variable`.

## Features

- **Raw protocol parsing:** Ethernet, IPv4, TCP and UDP headers are parsed from byte buffers with proper network byte order handling (`ntohs`/`ntohl`), without libpcap.
- **TLS SNI extraction:** walks the Client Hello (record header, handshake header, session ID, cipher suites, compression methods, extensions) to read the Server Name Indication. The SNI is sent in plaintext before encryption starts, which is why it can be read on HTTPS connections.
- **HTTP Host extraction:** used for plaintext HTTP traffic.
- **Flow tracking:** a table keyed by `{src_ip, dst_ip, src_port, dst_port, protocol}` keeps classification and block decisions consistent for the whole connection.
- **Blocking rules:** by source IP, by application (YouTube, TikTok, Facebook, etc.), or by domain (substring match on the SNI/Host).
- **Report:** total, forwarded and dropped packets, work per thread, application breakdown in percent, and the list of detected domains.

## Project structure

```
packet_analyzer/
├── include/
│   ├── pcap_reader.h          # PCAP file I/O
│   ├── packet_parser.h        # Ethernet/IP/TCP/UDP parsing
│   ├── sni_extractor.h        # TLS SNI and HTTP Host extraction
│   ├── types.h                # FiveTuple, Flow, AppType
│   ├── rule_manager.h         # Blocking rules
│   ├── connection_tracker.h   # Flow table
│   ├── load_balancer.h        # Load balancer thread
│   ├── fast_path.h            # Fast path worker thread
│   ├── thread_safe_queue.h    # Generic mutex-based MPMC queue
│   └── dpi_engine.h           # Top-level orchestrator
├── src/
│   ├── pcap_reader.cpp
│   ├── packet_parser.cpp
│   ├── sni_extractor.cpp
│   ├── types.cpp
│   ├── main_working.cpp       # Single-threaded version
│   └── dpi_mt.cpp             # Multi-threaded version
├── generate_test_pcap.py      # Generates a synthetic test PCAP
├── test_dpi.pcap              # Sample capture
└── README.md
```

## Build

Requirements: Linux or macOS, and a C++17 compiler (`g++` or `clang++`). No external libraries.

Single-threaded:
```bash
g++ -std=c++17 -O2 -I include -o dpi_simple \
    src/main_working.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

Multi-threaded:
```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/dpi_mt.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

## Usage

Classify only:
```bash
./dpi_engine test_dpi.pcap output.pcap
```

With blocking rules:
```bash
./dpi_engine test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

Change thread counts:
```bash
./dpi_engine input.pcap output.pcap --lbs 4 --fps 4
# 4 load balancers, 4 fast path workers per load balancer = 16 fast path threads
```

Generate the test capture:
```bash
python3 generate_test_pcap.py
```

## Sample output

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
║ DNS                   4   5.2% #                              ║
║ Facebook              3   3.9%                                ║
╚══════════════════════════════════════════════════════════════╝
```

## Design decisions

- **Blocking at flow level, not packet level.** The app is only known once the TLS Client Hello arrives, so the first packets of a flow are forwarded. After the flow is identified as blocked, every later packet of that flow is dropped. Real DPI devices work in a similar way.
- **Hash-based flow affinity.** Both dispatch stages use `hash(5-tuple) % N`. This keeps packets of a flow in order and lets the flow table live in a single thread without locks. It is plain modulo hashing, not a consistent-hash ring, so changing the thread count remaps flows. That is fine here because the thread count is fixed for a run.
- **No packet library.** Parsing Ethernet, IP, TCP and TLS by hand was the main learning goal, so I did not use libpcap or similar.

## Limitations

- Works on PCAP files only. There is no live capture.
- IPv4 only.
- SNI cannot be read from QUIC traffic or from TLS connections that use Encrypted Client Hello.
- The first packets of a flow are forwarded before it can be identified.
- Domain rules are substring matches, so a short pattern can block more than intended.
- No automated tests and no benchmarks. It was checked against the bundled synthetic capture (77 packets), so the multi-threaded speedup is not measured.

## Roadmap

- [ ] QUIC / HTTP-3 SNI extraction
- [ ] Bandwidth throttling instead of only blocking
- [ ] Load rules from a file
- [ ] Live per-second statistics in the terminal
- [ ] More application signatures
- [ ] Unit tests and a throughput benchmark

## License

MIT. See [LICENSE](LICENSE).
