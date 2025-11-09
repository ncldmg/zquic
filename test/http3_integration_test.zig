const std = @import("std");
const quic = @import("quic");
const http3 = @import("http3");
const server_mod = @import("server");

/// Simple QUIC client for testing
const QuicClient = struct {
    sockfd: std.posix.socket_t,
    server_addr: std.net.Address,
    dcid: quic.ConnectionId,
    scid: quic.ConnectionId,

    pub fn init(server_addr: std.net.Address) !QuicClient {
        const sockfd = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);

        // Generate random connection IDs
        var dcid = quic.ConnectionId{};
        dcid.len = 8;
        var prng = std.Random.DefaultPrng.init(@as(u64, @intCast(std.time.milliTimestamp())));
        const random = prng.random();
        random.bytes(dcid.data[0..8]);

        var scid = quic.ConnectionId{};
        scid.len = 8;
        random.bytes(scid.data[0..8]);

        return QuicClient{
            .sockfd = sockfd,
            .server_addr = server_addr,
            .dcid = dcid,
            .scid = scid,
        };
    }

    pub fn deinit(self: *QuicClient) void {
        std.posix.close(self.sockfd);
    }

    /// Send HTTP/3 request over QUIC Initial packet
    pub fn sendHttp3Request(self: *QuicClient, request: http3.Request) !void {
        // Encode HTTP/3 request
        var http3_buf: [1024]u8 = undefined;
        const http3_len = try request.encode(&http3_buf);

        std.debug.print("Client: Encoded HTTP/3 request: {d} bytes\n", .{http3_len});

        // Create STREAM frame using QUIC encoder
        const stream_frame = quic.StreamFrame{
            .stream_id = 0, // Bidirectional client-initiated stream
            .offset = 0,
            .length = http3_len,
            .data = http3_buf[0..http3_len],
            .fin = true,
        };

        var stream_buf: [1200]u8 = undefined;
        const stream_len = try stream_frame.encode(&stream_buf);

        std.debug.print("Client: Encoded STREAM frame: {d} bytes\n", .{stream_len});

        // Create QUIC Initial packet using proper encoder
        const initial_header = quic.LongHeader{
            .packet_type = .initial,
            .version = .version_1,
            .dcid = self.dcid,
            .scid = self.scid,
            .token = null,
            .length = 0, // Will be calculated by encoder
            .packet_number = 1,
            .payload = stream_buf[0..stream_len],
        };

        var packet_buf: [2048]u8 = undefined;
        var packet_len = try quic.Encoder.encodeLongHeader(initial_header, &packet_buf);

        // Pad to minimum 1200 bytes for Initial packet (RFC 9000 Section 14.1)
        const min_packet_size = 1200;
        if (packet_len < min_packet_size) {
            // Add PADDING frames (0x00)
            @memset(packet_buf[packet_len..min_packet_size], 0x00);
            packet_len = min_packet_size;
        }

        std.debug.print("Client: Total packet size: {d} bytes (padded to {d})\n", .{ packet_len, min_packet_size });

        // Send packet
        _ = try std.posix.sendto(
            self.sockfd,
            packet_buf[0..packet_len],
            0,
            &self.server_addr.any,
            self.server_addr.getOsSockLen(),
        );
    }

    /// Receive response from server and decode HTTP/3 body
    /// Copies the body into the provided buffer and returns a slice
    pub fn receiveResponse(self: *QuicClient, timeout_ms: u64, response_buf: []u8) ![]const u8 {
        var buf: [2048]u8 = undefined;

        // Set socket timeout
        const timeout = std.posix.timeval{
            .sec = @intCast(timeout_ms / 1000),
            .usec = @intCast((timeout_ms % 1000) * 1000),
        };
        try std.posix.setsockopt(
            self.sockfd,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVTIMEO,
            std.mem.asBytes(&timeout),
        );

        var src_addr: std.posix.sockaddr = undefined;
        var addrlen: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);

        const len = try std.posix.recvfrom(self.sockfd, &buf, 0, &src_addr, &addrlen);
        const data = buf[0..len];

        // Parse QUIC packet
        const packet = try quic.Parser.parse(data);
        const payload = packet.getPayload();

        // Parse STREAM frame from QUIC payload to extract HTTP/3 data
        const stream_frame = try http3.StreamFrame.parse(payload);

        // Now parse HTTP/3 frames from the stream data to extract body
        const body = try http3.parseHttp3Body(stream_frame.data);

        // Copy body to provided buffer to avoid use-after-free
        const copy_len = @min(body.len, response_buf.len);
        @memcpy(response_buf[0..copy_len], body[0..copy_len]);
        return response_buf[0..copy_len];
    }
};

/// Helper to send HTTP/3 response over QUIC
fn sendHttp3Response(sockfd: std.posix.socket_t, response: http3.Response, dest_addr: std.net.Address, dcid: quic.ConnectionId, scid: quic.ConnectionId, packet_number: u32) !void {
    // Encode HTTP/3 response
    var http3_buf: [1024]u8 = undefined;
    const http3_len = try response.encode(&http3_buf);

    // Create STREAM frame
    const stream_frame = quic.StreamFrame{
        .stream_id = 0,
        .offset = 0,
        .length = http3_len,
        .data = http3_buf[0..http3_len],
        .fin = true,
    };

    var stream_buf: [1200]u8 = undefined;
    const stream_len = try stream_frame.encode(&stream_buf);

    // Create QUIC Initial packet (in real QUIC, response would use Handshake/1-RTT packet)
    const response_header = quic.LongHeader{
        .packet_type = .initial,
        .version = .version_1,
        .dcid = dcid, // Swap: client's SCID becomes server's DCID
        .scid = scid, // Server's connection ID
        .token = null,
        .length = 0,
        .packet_number = packet_number,
        .payload = stream_buf[0..stream_len],
    };

    var packet_buf: [2048]u8 = undefined;
    const packet_len = try quic.Encoder.encodeLongHeader(response_header, &packet_buf);

    // Send response packet
    _ = try std.posix.sendto(
        sockfd,
        packet_buf[0..packet_len],
        0,
        &dest_addr.any,
        dest_addr.getOsSockLen(),
    );

    std.debug.print("Server sent HTTP/3 response: \"{s}\"\n", .{response.body});
}

test "HTTP/3 client-server real communication" {
    const server_addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 14433);

    // Create and start server
    const conf = server_mod.Config{ .address = server_addr };
    const handler = server_mod.Handler.init(http3.http3Handle);
    var srv = server_mod.Server.init(conf, handler);
    defer srv.deinit();

    try srv.start();

    // Server thread that receives request and sends response
    const ServerThread = struct {
        server: *server_mod.Server,

        fn run(self: *@This()) void {
            var buf: [2048]u8 = undefined;
            var src_addr: std.posix.sockaddr = undefined;
            var addrlen: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);

            // Set a receive timeout
            const timeout = std.posix.timeval{
                .sec = 3,
                .usec = 0,
            };
            std.posix.setsockopt(
                self.server.sockfd.?,
                std.posix.SOL.SOCKET,
                std.posix.SO.RCVTIMEO,
                std.mem.asBytes(&timeout),
            ) catch return;

            // Wait for request packet
            const len = std.posix.recvfrom(self.server.sockfd.?, &buf, 0, &src_addr, &addrlen) catch |err| {
                std.debug.print("Server receive error: {}\n", .{err});
                return;
            };

            const data = buf[0..len];
            const src = std.net.Address.initPosix(@alignCast(&src_addr));

            // Parse QUIC packet
            const packet = quic.Parser.parse(data) catch |err| {
                std.debug.print("Parse error: {}\n", .{err});
                return;
            };

            // Handle packet (prints the request)
            self.server.handler.handlePacket(packet, src);

            // Send HTTP/3 response back to client
            const response = http3.Response{
                .status = "200",
                .body = "Hello from server!",
            };

            // Extract connection IDs from request packet
            var server_cid = quic.ConnectionId{};
            server_cid.len = 8;
            var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp() + 100));
            prng.random().bytes(server_cid.data[0..8]);

            const client_scid = switch (packet) {
                .long_header => |h| h.scid,
                .short_header => |h| h.dcid,
            };

            sendHttp3Response(
                self.server.sockfd.?,
                response,
                src,
                client_scid, // Client's SCID becomes our DCID
                server_cid, // Our new SCID
                2,
            ) catch |err| {
                std.debug.print("Failed to send response: {}\n", .{err});
            };
        }
    };

    // Start server in thread
    var server_ctx = ServerThread{ .server = &srv };
    const thread = try std.Thread.spawn(.{}, ServerThread.run, .{&server_ctx});

    // Give server time to start
    std.Thread.sleep(100 * std.time.ns_per_ms);

    // Create client and send request
    var client = try QuicClient.init(server_addr);
    defer client.deinit();

    const request = http3.Request{
        .method = "POST",
        .path = "/api/test",
        .scheme = "https",
        .authority = "localhost:14433",
        .body = "Hello, World!",
    };

    // Send HTTP/3 request over QUIC
    try client.sendHttp3Request(request);
    std.debug.print("✓ Client sent HTTP/3 request: \"Hello, World!\"\n", .{});

    // Receive response from server
    var response_buf: [256]u8 = undefined;
    const response_body = try client.receiveResponse(2000, &response_buf);
    std.debug.print("✓ Client received HTTP/3 response: \"{s}\"\n", .{response_body});

    // Verify response
    try std.testing.expectEqualStrings("Hello from server!", response_body);

    // Wait for server thread to finish
    thread.join();

    std.debug.print("✓ HTTP/3 bidirectional communication test PASSED!\n", .{});
}

test "HTTP/3 request/response roundtrip encoding" {
    const allocator = std.testing.allocator;

    // Test 1: Request roundtrip (encode → decode → verify)
    {
        const original_request = http3.Request{
            .method = "POST",
            .path = "/api/data",
            .scheme = "https",
            .authority = "api.example.com",
            .body = "test data",
        };

        // Encode the request
        var req_buf: [1024]u8 = undefined;
        const req_len = try original_request.encode(&req_buf);
        try std.testing.expect(req_len > 0);
        std.debug.print("Encoded HTTP/3 request: {d} bytes\n", .{req_len});

        // Decode the request
        const decoded_request = try http3.decodeRequest(req_buf[0..req_len], allocator);
        defer {
            if (decoded_request.method) |m| allocator.free(m);
            if (decoded_request.path) |p| allocator.free(p);
            if (decoded_request.scheme) |s| allocator.free(s);
            if (decoded_request.authority) |a| allocator.free(a);
        }

        // Verify decoded values match original
        try std.testing.expect(decoded_request.method != null);
        try std.testing.expectEqualStrings("POST", decoded_request.method.?);

        try std.testing.expect(decoded_request.path != null);
        try std.testing.expectEqualStrings("/api/data", decoded_request.path.?);

        try std.testing.expect(decoded_request.scheme != null);
        try std.testing.expectEqualStrings("https", decoded_request.scheme.?);

        try std.testing.expect(decoded_request.authority != null);
        try std.testing.expectEqualStrings("api.example.com", decoded_request.authority.?);

        try std.testing.expect(decoded_request.body != null);
        try std.testing.expectEqualStrings("test data", decoded_request.body.?);

        std.debug.print("✓ Request roundtrip successful: all fields match\n", .{});
    }

    // Test 2: Response roundtrip (encode → decode → verify)
    {
        const original_response = http3.Response{
            .status = "200",
            .body = "Hello from server!",
        };

        // Encode the response
        var resp_buf: [1024]u8 = undefined;
        const resp_len = try original_response.encode(&resp_buf);
        try std.testing.expect(resp_len > 0);
        std.debug.print("Encoded HTTP/3 response: {d} bytes\n", .{resp_len});

        // Decode the response
        const decoded_response = try http3.decodeResponse(resp_buf[0..resp_len], allocator);
        defer {
            if (decoded_response.status) |s| allocator.free(s);
        }

        // Verify decoded values match original
        try std.testing.expect(decoded_response.status != null);
        try std.testing.expectEqualStrings("200", decoded_response.status.?);

        try std.testing.expect(decoded_response.body != null);
        try std.testing.expectEqualStrings("Hello from server!", decoded_response.body.?);

        std.debug.print("✓ Response roundtrip successful: all fields match\n", .{});
    }

    // Test 3: Edge cases
    {
        // Empty body
        const empty_request = http3.Request{
            .method = "GET",
            .path = "/",
            .scheme = "https",
            .authority = "example.com",
            .body = "",
        };

        var buf: [1024]u8 = undefined;
        const len = try empty_request.encode(&buf);

        const decoded = try http3.decodeRequest(buf[0..len], allocator);
        defer {
            if (decoded.method) |m| allocator.free(m);
            if (decoded.path) |p| allocator.free(p);
            if (decoded.scheme) |s| allocator.free(s);
            if (decoded.authority) |a| allocator.free(a);
        }

        try std.testing.expectEqualStrings("GET", decoded.method.?);
        try std.testing.expectEqualStrings("/", decoded.path.?);
        // Empty body should result in no DATA frame, so body is null
        try std.testing.expect(decoded.body == null);

        std.debug.print("✓ Edge case (empty body) handled correctly\n", .{});
    }

    std.debug.print("✓ All HTTP/3 roundtrip encoding/decoding tests PASSED!\n", .{});

    // Test 4: Real network communication with full roundtrip (request → server → response → client)
    {
        const server_addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 14434); // Different port than test 1

        // Create and start server
        const conf = server_mod.Config{ .address = server_addr };
        const handler = server_mod.Handler.init(http3.http3Handle);
        var srv = server_mod.Server.init(conf, handler);
        defer srv.deinit();

        try srv.start();

        // Server thread that receives request and sends response
        const ServerThread = struct {
            server: *server_mod.Server,

            fn run(self: *@This()) void {
                var buf: [2048]u8 = undefined;
                var src_addr: std.posix.sockaddr = undefined;
                var addrlen: std.posix.socklen_t = @sizeOf(std.posix.sockaddr);

                // Set a receive timeout
                const timeout = std.posix.timeval{
                    .sec = 3,
                    .usec = 0,
                };
                std.posix.setsockopt(
                    self.server.sockfd.?,
                    std.posix.SOL.SOCKET,
                    std.posix.SO.RCVTIMEO,
                    std.mem.asBytes(&timeout),
                ) catch return;

                // Wait for request packet
                const len = std.posix.recvfrom(self.server.sockfd.?, &buf, 0, &src_addr, &addrlen) catch |err| {
                    std.debug.print("Server receive error: {}\n", .{err});
                    return;
                };

                const data = buf[0..len];
                const src = std.net.Address.initPosix(@alignCast(&src_addr));

                // Parse QUIC packet
                const packet = quic.Parser.parse(data) catch |err| {
                    std.debug.print("Parse error: {}\n", .{err});
                    return;
                };

                // Handle packet (prints the request)
                self.server.handler.handlePacket(packet, src);

                // Send different response based on test
                const response = http3.Response{
                    .status = "200",
                    .body = "Roundtrip response!",
                };

                // Extract connection IDs from request packet
                var server_cid = quic.ConnectionId{};
                server_cid.len = 8;
                var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp() + 200));
                prng.random().bytes(server_cid.data[0..8]);

                const client_scid = switch (packet) {
                    .long_header => |h| h.scid,
                    .short_header => |h| h.dcid,
                };

                sendHttp3Response(
                    self.server.sockfd.?,
                    response,
                    src,
                    client_scid,
                    server_cid,
                    2,
                ) catch |err| {
                    std.debug.print("Failed to send response: {}\n", .{err});
                };
            }
        };

        // Start server in thread
        var server_ctx = ServerThread{ .server = &srv };
        const thread = try std.Thread.spawn(.{}, ServerThread.run, .{&server_ctx});

        // Give server time to start
        std.Thread.sleep(100 * std.time.ns_per_ms);

        // Create client and send request
        var client = try QuicClient.init(server_addr);
        defer client.deinit();

        const request = http3.Request{
            .method = "GET",
            .path = "/test/roundtrip",
            .scheme = "https",
            .authority = "localhost:14434",
            .body = "Roundtrip request!",
        };

        // Send HTTP/3 request over QUIC
        try client.sendHttp3Request(request);
        std.debug.print("✓ Client sent HTTP/3 request: \"Roundtrip request!\"\n", .{});

        // Receive response from server
        var response_buf: [256]u8 = undefined;
        const response_body = try client.receiveResponse(2000, &response_buf);
        std.debug.print("✓ Client received HTTP/3 response: \"{s}\"\n", .{response_body});

        // Verify response
        try std.testing.expectEqualStrings("Roundtrip response!", response_body);

        // Wait for server thread to finish
        thread.join();

        std.debug.print("✓ Network roundtrip test (with response) PASSED!\n", .{});
    }

    std.debug.print("✓ All HTTP/3 roundtrip tests (encoding + bidirectional network) PASSED!\n", .{});
}
