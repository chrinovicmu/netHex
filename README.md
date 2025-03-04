# Network Packet Sniffer

## Overview

This is a lightweight, high-performance network packet capture and analysis tool written in C, designed to intercept and examine network traffic using libpcap. The project focuses on providing detailed packet inspection capabilities with an efficient ring buffer implementation for handling network packets.

## 🚧 Project Status: Work in Progress 🚧

**Current State:** Active development, with core functionality for packet capture and basic analysis implemented. The project is undergoing continuous improvements and refinement.

## Features

- Live network interface packet capture
- Support for multiple network protocols (TCP, UDP, ICMP)
- Detailed packet payload analysis
- Configurable packet filtering
- Ring buffer-based packet storage
- Hex and ASCII payload representation

## Prerequisites

- libpcap development libraries
- GCC compiler with C11 support
- Linux/UNIX-based operating system
- GNU Make version 4.3  

## Dependencies

- libpcap
- Standard C libraries

## Compilation

```bash
make build 
```

## Usage
Will require root privileges 

```bash
make run 
```

## Current Limitations

- Limited to UDP packet capture by default
- Statically configured ring buffer size
- Minimal error handling
- non mutlithreaded

## Roadmap

- [ ] Enhance protocol support
- [ ] Implement more robust error handling
- [ ] Add configurable filtering options
- [ ] Improve memory management
- [ ] Create logging mechanisms

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[To be determined ]

## Disclaimer

This tool is for educational and network diagnostic purposes. Always ensure you have proper authorization before capturing network traffic.
