# zquic

A QUIC protocol implementation in Zig.

## Features

- WIP

## Requirements

- Zig 0.15.1 or later

## Building

```bash
zig build
```

## Running

```bash
zig build run
```

Or run the built executable directly:

```bash
./zig-out/bin/zquic
```

The server listens on `0.0.0.0:4433` by default. Press `Ctrl+C` to stop the server gracefully.

## Testing

Run all tests:

```bash
zig build test
```

Run specific test file:

```bash
zig test src/server.zig
```

## License

MIT
