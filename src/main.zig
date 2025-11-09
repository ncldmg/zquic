const std = @import("std");
const cli = @import("cli");
const quic = @import("quic");
const http3 = @import("http3.zig");
const posix = std.posix;

const server_mod = @import("server.zig");
const Server = server_mod.Server;
const Config = server_mod.Config;
const Handler = server_mod.Handler;

var config = struct {
    host: []const u8 = "localhost",
    port: u16 = undefined,
}{};

pub fn main() !void {
    var act = posix.Sigaction{
        .handler = .{ .handler = signalHandler },
        .mask = posix.sigemptyset(),
        .flags = 0,
    };

    posix.sigaction(posix.SIG.INT, &act, null);
    posix.sigaction(posix.SIG.TERM, &act, null);

    var r = try cli.AppRunner.init(std.heap.page_allocator);

    const app = cli.App{
        .command = cli.Command{
            .name = "short",
            .options = try r.allocOptions(&.{
                .{
                    .long_name = "host",
                    .help = "host to listen on",
                    .required = true,
                    .value_ref = r.mkRef(&config.host),
                },

                // Define an Option for the "port" command-line argument.
                .{
                    .long_name = "port",
                    .help = "port to bind to",
                    .required = true,
                    .value_ref = r.mkRef(&config.port),
                },
            }),
            .target = cli.CommandTarget{
                .action = cli.CommandAction{ .exec = StartServerCmd },
            },
        },
    };
    return r.run(&app);
}

fn StartServerCmd() !void {
    const gpa = std.heap.page_allocator;
    var address_list = try std.net.getAddressList(gpa, config.host, config.port);
    defer address_list.deinit();

    const address = address_list.addrs[0];

    const conf = Config{
        .address = address,
        .reuse_address = true,
    };

    const handler = Handler.init(http3.http3Handle);
    var srv = Server.init(conf, handler);
    defer srv.deinit();

    std.debug.print("Starting server on {s}:{d}...\n", .{ config.host, config.port });
    try srv.start();
    try srv.run();
    std.debug.print("Server stopped gracefully\n", .{});
}

// Import the should_exit from server module
const should_exit_ptr = &@import("server.zig").should_exit;

fn signalHandler(sig: c_int) callconv(.c) void {
    std.debug.print("\nReceived signal {d}, shutting down...\n", .{sig});
    should_exit_ptr.store(true, .release);
}
