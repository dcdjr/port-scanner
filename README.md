# Multithreaded TCP Port Scanner (C, Winsock2)

A high-performance, multithreaded TCP port scanner written in C for Windows.  
Includes banner grabbing, safe thread dispatching, timing statistics, and service name detection.

---

## Features

- Multithreaded scanning (1000+ threads supported)
- Fast mode (`--fast`) → no banner grabbing
- Full mode (`--full`) → banner grabbing enabled (default)
- Thread-safe console + file logging
- Service name identification for common ports
- Output logged to `scan_results.txt`
- Timing statistics (ports/sec, total runtime)
- Clean queue-based architecture and no race conditions

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
port_scanner.exe <ip> [start_port end_port] <num_threads> [--fast|--full]
```

---

## Example Commands

Standard scan on a demo IP
```bash
port_scanner.exe 192.0.2.10
```

Custom range + threads + full mode
```bash
port_scanner.exe 198.51.100.25 1 5000 200 --full
```

Fast scan
```bash
port_scanner.exe 203.0.113.7 1 65535 500 --fast
```

---

## Output Example

Console output looks like:

```csharp
[Thread 3] Port 22 OPEN (SSH)
[Thread 5] Port 80 OPEN - banner: Apache/2.4.41
[Thread 12] Port 443 OPEN (HTTPS)
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
