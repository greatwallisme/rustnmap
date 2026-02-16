# rustnmap-common

Common types, errors, and utilities for the RustNmap network scanner.

## Purpose

This crate provides foundational types and utilities used across all other crates in the RustNmap workspace. It contains no external network dependencies and serves as the base layer of the architecture.

## Key Components

### Types

- `Port` - Port number with protocol (TCP/UDP/SCTP)
- `PortRange` - Inclusive range of ports
- `Target` - Scan target (IP address or hostname)
- `ScanType` - Enumeration of all supported scan types
- `PortState` - Port state (Open, Closed, Filtered, etc.)

### Errors

- `Error` - Main error type using `thiserror`
- `Result<T>` - Type alias for `std::result::Result<T, Error>`

## Dependencies

| Crate | Purpose |
|-------|---------|
| thiserror | Error derive macros |
| serde | Serialization |

## Testing

```bash
cargo test -p rustnmap-common
```

## Usage

```rust
use rustnmap_common::{Port, PortState, ScanType};

let port = Port::new(80, Protocol::Tcp);
assert_eq!(port.state, PortState::Open);
```

## Design Notes

- Keep this crate minimal and dependency-light
- All types must implement `Clone`, `Debug`, and `Serialize`
- Use `thiserror` for ergonomic error handling
