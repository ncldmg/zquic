const std = @import("std");
const zquic = @import("zquic");
const posix = std.posix;

const server_mod = @import("server.zig");
const Server = server_mod.Server;
const Config = server_mod.Config;
const Handler = server_mod.Handler;

// Import the should_exit from server module
const should_exit_ptr = &@import("server.zig").should_exit;

fn signalHandler(sig: c_int) callconv(.c) void {
    std.debug.print("\nReceived signal {d}, shutting down...\n", .{sig});
    should_exit_ptr.store(true, .release);
}

fn defaultPacketHandler(data: []const u8, src: std.net.Address) void {
    std.debug.print("Got {d} bytes from {any}\n", .{ data.len, src });
    // TODO: parse QUIC packet header
}

pub fn main() !void {
    // Set up signal handlers
    var act = posix.Sigaction{
        .handler = .{ .handler = signalHandler },
        .mask = posix.sigemptyset(),
        .flags = 0,
    };

    posix.sigaction(posix.SIG.INT, &act, null);
    posix.sigaction(posix.SIG.TERM, &act, null);

    // Create server configuration
    const conf = Config.default();

    // Create handler
    const handler = Handler.init(defaultPacketHandler);

    // Create and start server
    var srv = Server.init(conf, handler);
    defer srv.deinit();

    std.debug.print("Starting server... Press Ctrl+C to stop\n", .{});
    try srv.start();
    try srv.run();
    std.debug.print("Server stopped gracefully\n", .{});
}
