# AnyTLS-rs

A Rust implementation of the AnyTLS protocol - a proxy protocol designed to mitigate nested TLS handshake fingerprinting (TLS in TLS) issues.

This implementation is fully compatible with the [Go reference implementation](https://github.com/anytls/anytls-go).

## Features

- **Flexible packet splitting and padding strategies** - Configurable schemes to obfuscate traffic patterns
- **Connection multiplexing** - Reduces proxy latency by reusing connections
- **Simple configuration** - Minimal setup required
- **Cross-platform** - Supports Linux, Windows, and macOS
- **Protocol v2 support** - Including SYNACK responses and heartbeat packets

## Quick Start

### Server

```bash
./anytls-server -l 0.0.0.0:8443 -p your_password
```

`0.0.0.0:8443` is the server listening address and port.

### Client

```bash
./anytls-client -l 127.0.0.1:1080 -s server_ip:port -p your_password
```

`127.0.0.1:1080` is the local SOCKS5 proxy listening address. Both TCP and UDP (via UDP-over-TCP) are supported.

## Command Line Options

### Client

```
anytls-client [OPTIONS]

OPTIONS:
    -l, --listen <LISTEN>          Local SOCKS5 listen address [default: 127.0.0.1:1080]
    -s, --server <SERVER>          Server address
    -p, --password <PASSWORD>      Password
        --sni <SNI>                Server Name Indication [default: ""]
        --log-level <LOG_LEVEL>    Log level [default: info]
    -h, --help                     Print help
    -V, --version                  Print version
```

### Server

```
anytls-server [OPTIONS]

OPTIONS:
    -l, --listen <LISTEN>                      Server listen address [default: 0.0.0.0:8443]
    -p, --password <PASSWORD>                  Password
        --padding-scheme <PADDING_SCHEME>      Padding scheme file
        --log-level <LOG_LEVEL>                Log level [default: info]
    -h, --help                                 Print help
    -V, --version                              Print version
```

## Building from Source

### Prerequisites

- Rust 1.70 or later
- Cargo

### Build

```bash
# Clone the repository
git clone https://github.com/yourusername/anytls-rs.git
cd anytls-rs

# Build release binaries
cargo build --release

# Binaries will be in:
# target/release/anytls-client
# target/release/anytls-server
```

## Protocol Documentation

- [Protocol Specification](https://github.com/anytls/anytls-go/blob/main/docs/protocol.md)
- [FAQ](https://github.com/anytls/anytls-go/blob/main/docs/faq.md)
- [URI Scheme](https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md)

## Padding Scheme

The default padding scheme is designed to obfuscate packet patterns. You can customize it by creating a file with the following format:

```
stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000
```

Then use it with the server:

```bash
./anytls-server -l 0.0.0.0:8443 -p your_password --padding-scheme ./custom_padding.txt
```

## Compatibility

This Rust implementation is wire-compatible with:

- [anytls-go](https://github.com/anytls/anytls-go) - Reference Go implementation
- [sing-box](https://github.com/SagerNet/sing-box) - Merged in dev-next branch
- [mihomo](https://github.com/MetaCubeX/mihomo) - Merged in Alpha branch
- Shadowrocket 2.2.65+ - iOS client

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- Original [anytls-go](https://github.com/anytls/anytls-go) implementation
- Projects referenced in the original implementation:
  - [smux](https://github.com/xtaci/smux)
  - [restls](https://github.com/3andne/restls)
  - [sing-box](https://github.com/SagerNet/sing-box)
  - [naiveproxy](https://github.com/klzgrad/naiveproxy) 