# Multithreaded TCP Port Scanner (C, Winsock2)

A high-performance, multithreaded TCP port scanner written in C for Windows.  
Includes banner grabbing, safe thread dispatching, timing statistics, service name detection, configurable timeouts, and colored console output.

---

## Features

- Multithreaded scanning (user-defined thread count)
- Fast mode (`--fast`) → no banner grabbing
- Full mode (`--full`) → banner grabbing enabled (default)
- Configurable timeout per connection via `--timeout <ms>`
- Thread-safe console and file logging with mutexes
- Colored console output for open ports (ANSI escape codes)
- Service name identification for common ports (SSH, HTTP, RDP, etc.)
- Output logged to `scan_results.txt`
- Timing statistics: total runtime and ports per second
- Clean queue-based architecture (one shared job queue, many workers)

---

## Build Instructions (Windows)

Requires:

- MinGW-w64 or MSYS2  
- pthreads for Windows  
- Winsock2 libraries

Compile:

```bash
gcc port_scanner.c -o port_scanner.exe -lws2_32 -lpthread
```

---

## Usage

```c
port_scanner.exe <ip> [start_port end_port] <num_threads> [--fast|--full] [--timeout ms]
```

| Parameter               | Description                                                  |
| ----------------------- | ------------------------------------------------------------ |
| `<ip>`                  | Target IPv4 address                                          |
| `[start_port end_port]` | Optional port range (defaults to `1–1023`)                   |
| `<num_threads>`         | Optional thread count (defaults to `50`)                     |
| `--fast`                | Disable banner grabbing (connect scan only)                  |
| `--full`                | Enable banner grabbing (default behavior)                    |
| `--timeout ms`          | Set socket send/recv timeout in milliseconds (default `200`) |

Examples of valid argument orders:
```bash
port_scanner.exe 192.0.2.10
```

```bash
port_scanner.exe 192.0.2.10 1 1024 100 --fast --timeout 100
```

```bash
port_scanner.exe 198.51.100.25 1 5000 200 --full --timeout 300
```

---

## Example Commands

Use RFC 5737 test addresses or your own lab machines / VMs.

Standard scan on a demo IP (default ports 1–1023, full mode):
```bash
port_scanner.exe 192.0.2.10
```

Custom range + threads + full mode:
```bash
port_scanner.exe 198.51.100.25 1 5000 200 --full
```

Fast full-range scan with lower timeout:
```bash
port_scanner.exe 203.0.113.7 1 65535 500 --fast --timeout 100
```

Only scan systems you own or have explicit permission to test.

---

## Output Example

Console output looks like:

```csharp
Scanning 45.33.32.156 (ports 1–1024) with 50 threads, mode=full, timeout=200 ms...
[Thread 20] Port 22 OPEN - banner: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13 (SSH)
[Thread 42] Port 80 OPEN (HTTP)
Scan complete.
Total scan time: 71.22 seconds
Ports per second: 14.38
```

All results are written to:

```bash
scan_results.txt
```

You will generate your own example once you scan a real target.

---

## Project Structure

```bash
port_scanner.c      # Main source code
scan_results.txt    # Output generated from scans
README.md           # Documentation (this file)
```


