const std = @import("std");
const zquic = @import("zquic");
const posix = std.posix;
const quic = @import("quic");
const format = @import("format");

pub const Config = struct {
    address: std.net.Address,
    reuse_address: bool = true,

    pub fn init(addr: [4]u8, port: u16) Config {
        return .{
            .address = std.net.Address.initIp4(addr, port),
        };
    }

    pub fn default() Config {
        return init([4]u8{ 0, 0, 0, 0 }, 4433);
    }
};

/// Handler for parsed QUIC packets
pub const Handler = struct {
    onPacketFn: *const fn (packet: quic.Packet, src: std.net.Address) void,

    pub fn init(onPacket: *const fn (packet: quic.Packet, src: std.net.Address) void) Handler {
        return .{ .onPacketFn = onPacket };
    }

    pub fn handlePacket(self: Handler, packet: quic.Packet, src: std.net.Address) void {
        self.onPacketFn(packet, src);
    }
};

pub var should_exit = std.atomic.Value(bool).init(false);

pub const Server = struct {
    conf: Config,
    handler: Handler,
    sockfd: ?posix.socket_t = null,

    pub fn init(conf: Config, handler: Handler) Server {
        return .{
            .conf = conf,
            .handler = handler,
        };
    }

    pub fn start(self: *Server) !void {
        // Create UDP socket
        self.sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
        errdefer if (self.sockfd) |fd| posix.close(fd);

        // Set SO_REUSEADDR
        if (self.conf.reuse_address) {
            const enable: i32 = 1;
            try posix.setsockopt(self.sockfd.?, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&enable));
        }

        // Bind to configured address
        try posix.bind(self.sockfd.?, &self.conf.address.any, self.conf.address.getOsSockLen());

        // Format and print server address
        var addr_buf: [128]u8 = undefined;
        const addr_str = format.formatAddress(self.conf.address, &addr_buf) catch "unknown";
        std.debug.print("Server listening on {s}\n", .{addr_str});
    }

    pub fn run(self: *Server) !void {
        if (self.sockfd == null) return error.ServerNotStarted;

        var buf: [2048]u8 = undefined;

        while (!should_exit.load(.acquire)) {
            // Set a timeout so we can check the exit flag periodically
            const timeout = posix.timespec{
                .sec = 1,
                .nsec = 0,
            };

            var poll_fd = [_]posix.pollfd{.{
                .fd = self.sockfd.?,
                .events = posix.POLL.IN,
                .revents = 0,
            }};

            // Use ppoll which returns SignalInterrupt instead of auto-retrying
            const ready = posix.ppoll(&poll_fd, &timeout, null) catch |err| switch (err) {
                error.SignalInterrupt => {
                    // Signal received, check should_exit flag in next iteration
                    continue;
                },
                else => return err,
            };

            if (ready > 0) {
                var src_addr: posix.sockaddr = undefined;
                var addrlen: posix.socklen_t = @sizeOf(posix.sockaddr);
                const len = try posix.recvfrom(self.sockfd.?, &buf, 0, &src_addr, &addrlen);
                const data = buf[0..len];
                const src = std.net.Address.initPosix(@alignCast(&src_addr));

                // Parse QUIC packet
                const packet = quic.Parser.parse(data) catch |err| {
                    var src_buf: [128]u8 = undefined;
                    const src_str = format.formatAddress(src, &src_buf) catch "unknown";
                    std.debug.print("Failed to parse QUIC packet from {s}: {}\n", .{ src_str, err });
                    continue;
                };

                // Call the handler with parsed packet
                self.handler.handlePacket(packet, src);
            }
        }
    }

    pub fn stop(self: *Server) void {
        // Only set the exit flag, don't close the socket yet
        // The socket will be closed by deinit() after run() returns
        _ = self;
        should_exit.store(true, .release);
    }

    pub fn deinit(self: *Server) void {
        if (self.sockfd) |fd| {
            posix.close(fd);
            self.sockfd = null;
        }
    }
};

fn testPacketHandler(packet: quic.Packet, src: std.net.Address) void {
    _ = packet;
    _ = src;
    // Test handler - does nothing
}

const TestContext = struct {
    server: *Server,

    fn runServer(ctx: *TestContext) !void {
        try ctx.server.run();
    }
};

test "server start and stop" {
    // Reset the exit flag
    should_exit.store(false, .release);

    // Create server configuration
    const conf = Config.default();
    const handler = Handler.init(testPacketHandler);

    // Create server
    var srv = Server.init(conf, handler);
    defer srv.deinit();

    // Start server
    try srv.start();

    // Create context for thread
    var ctx = TestContext{ .server = &srv };

    // Run server in a separate thread
    const thread = try std.Thread.spawn(.{}, TestContext.runServer, .{&ctx});

    // Wait a bit for server to start
    std.Thread.sleep(100 * std.time.ns_per_ms);

    // Signal the server to stop
    srv.stop();

    // Wait for server to stop
    thread.join();

    // Verify it stopped successfully
    try std.testing.expect(should_exit.load(.acquire) == true);
}
