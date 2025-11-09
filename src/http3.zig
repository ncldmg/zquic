const std = @import("std");
const quic = @import("quic");
const format = @import("format");

/// QUIC STREAM Frame parser for HTTP/3
pub const StreamFrame = struct {
    stream_id: u64,
    offset: u64,
    data: []const u8,
    fin: bool,

    pub fn parse(data: []const u8) !StreamFrame {
        if (data.len < 2) return error.BufferTooSmall;

        var offset: usize = 0;
        const frame_type = data[offset];
        offset += 1;

        // Check if this is a STREAM frame (0x08-0x0f)
        if ((frame_type & 0xf8) != 0x08) return error.NotStreamFrame;

        // Extract flags from frame type
        const has_offset = (frame_type & 0x04) != 0;
        const has_length = (frame_type & 0x02) != 0;
        const has_fin = (frame_type & 0x01) != 0;

        // Parse stream ID
        const stream_id_varint = try quic.VarInt.parse(data[offset..]);
        offset += stream_id_varint.length;

        // Parse offset (if present)
        var stream_offset: u64 = 0;
        if (has_offset) {
            const offset_varint = try quic.VarInt.parse(data[offset..]);
            offset += offset_varint.length;
            stream_offset = offset_varint.value;
        }

        // Parse length (if present) and data
        var stream_data: []const u8 = undefined;
        if (has_length) {
            const length_varint = try quic.VarInt.parse(data[offset..]);
            offset += length_varint.length;
            const data_len: usize = @intCast(length_varint.value);
            if (data.len < offset + data_len) return error.BufferTooSmall;
            stream_data = data[offset .. offset + data_len];
        } else {
            // No length field means data extends to end of packet
            stream_data = data[offset..];
        }

        return StreamFrame{
            .stream_id = stream_id_varint.value,
            .offset = stream_offset,
            .data = stream_data,
            .fin = has_fin,
        };
    }
};

/// HTTP/3 Frame Types (RFC 9114 Section 7.2)
pub const FrameType = enum(u64) {
    data = 0x00,
    headers = 0x01,
    cancel_push = 0x03,
    settings = 0x04,
    push_promise = 0x05,
    goaway = 0x07,
    max_push_id = 0x0d,
    _,

    pub fn fromU64(value: u64) FrameType {
        return @enumFromInt(value);
    }
};

/// HTTP/3 Frame Header
pub const FrameHeader = struct {
    frame_type: FrameType,
    length: u64,

    pub fn parse(data: []const u8) !struct { header: FrameHeader, consumed: usize } {
        var offset: usize = 0;

        // Parse frame type
        const type_varint = try quic.VarInt.parse(data[offset..]);
        offset += type_varint.length;

        // Parse frame length
        const len_varint = try quic.VarInt.parse(data[offset..]);
        offset += len_varint.length;

        return .{
            .header = FrameHeader{
                .frame_type = FrameType.fromU64(type_varint.value),
                .length = len_varint.value,
            },
            .consumed = offset,
        };
    }
};

/// HTTP/3 DATA Frame
pub const DataFrame = struct {
    data: []const u8,

    pub fn serialize(self: DataFrame, buf: []u8) !usize {
        var offset: usize = 0;

        // Frame type (DATA = 0x00)
        const type_len = try quic.VarInt.encode(0x00, buf[offset..]);
        offset += type_len;

        // Frame length
        const len_encoded = try quic.VarInt.encode(self.data.len, buf[offset..]);
        offset += len_encoded;

        // Data payload
        if (buf.len < offset + self.data.len) return error.BufferTooSmall;
        @memcpy(buf[offset .. offset + self.data.len], self.data);
        offset += self.data.len;

        return offset;
    }
};

/// HTTP/3 HEADERS Frame
pub const HeadersFrame = struct {
    encoded_field_section: []const u8,

    pub fn serialize(self: HeadersFrame, buf: []u8) !usize {
        var offset: usize = 0;

        // Frame type (HEADERS = 0x01)
        const type_len = try quic.VarInt.encode(0x01, buf[offset..]);
        offset += type_len;

        // Frame length
        const len_encoded = try quic.VarInt.encode(self.encoded_field_section.len, buf[offset..]);
        offset += len_encoded;

        // Encoded field section (QPACK encoded headers)
        if (buf.len < offset + self.encoded_field_section.len) return error.BufferTooSmall;
        @memcpy(buf[offset .. offset + self.encoded_field_section.len], self.encoded_field_section);
        offset += self.encoded_field_section.len;

        return offset;
    }
};

/// HTTP/3 SETTINGS Frame
pub const SettingsFrame = struct {
    settings: []Setting,

    pub const Setting = struct {
        id: u64,
        value: u64,
    };

    pub fn serialize(self: SettingsFrame, buf: []u8) !usize {
        var offset: usize = 0;

        // Frame type (SETTINGS = 0x04)
        const type_len = try quic.VarInt.encode(0x04, buf[offset..]);
        offset += type_len;

        // Calculate payload length
        var payload_len: usize = 0;
        for (self.settings) |setting| {
            var temp_buf: [16]u8 = undefined;
            const id_len = try quic.VarInt.encode(setting.id, &temp_buf);
            const val_len = try quic.VarInt.encode(setting.value, &temp_buf);
            payload_len += id_len + val_len;
        }

        // Frame length
        const len_encoded = try quic.VarInt.encode(payload_len, buf[offset..]);
        offset += len_encoded;

        // Settings payload
        for (self.settings) |setting| {
            const id_len = try quic.VarInt.encode(setting.id, buf[offset..]);
            offset += id_len;
            const val_len = try quic.VarInt.encode(setting.value, buf[offset..]);
            offset += val_len;
        }

        return offset;
    }
};

/// Simple QPACK encoder for literal headers (no compression)
/// RFC 9204 - QPACK: Field Compression for HTTP/3
pub const QPack = struct {
    /// Encode headers as QPACK literal field lines (no dynamic table)
    pub fn encodeLiteralHeaders(headers: []const Header, buf: []u8) ![]const u8 {
        var offset: usize = 0;

        // Required Insert Count (0 for no dynamic table references)
        buf[offset] = 0x00;
        offset += 1;

        // Base (0 for no dynamic table)
        buf[offset] = 0x00;
        offset += 1;

        // Encode each header as literal name and value
        for (headers) |header| {
            // Literal field line with name and value
            // Format: 0010nnnn for literal name length prefix
            buf[offset] = 0x20; // Literal with literal name
            offset += 1;

            // Name length
            const name_len = try quic.VarInt.encode(header.name.len, buf[offset..]);
            offset += name_len;

            // Name value
            @memcpy(buf[offset .. offset + header.name.len], header.name);
            offset += header.name.len;

            // Value length
            const value_len = try quic.VarInt.encode(header.value.len, buf[offset..]);
            offset += value_len;

            // Value
            @memcpy(buf[offset .. offset + header.value.len], header.value);
            offset += header.value.len;
        }

        return buf[0..offset];
    }
};

/// HTTP header (name-value pair)
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// Parse HTTP/3 frames from stream data and extract body
pub fn parseHttp3Body(stream_data: []const u8) ![]const u8 {
    var offset: usize = 0;

    while (offset < stream_data.len) {
        // Parse frame header
        const result = try FrameHeader.parse(stream_data[offset..]);
        offset += result.consumed;

        const frame_len: usize = @intCast(result.header.length);

        // Check if this is a DATA frame
        if (result.header.frame_type == .data) {
            // Return the data payload
            if (stream_data.len < offset + frame_len) return error.BufferTooSmall;
            return stream_data[offset .. offset + frame_len];
        }

        // Skip this frame and continue looking
        offset += frame_len;
    }

    return error.NoDataFrame;
}

/// Decoded HTTP/3 request (parsed from encoded bytes)
pub const DecodedRequest = struct {
    method: ?[]const u8 = null,
    path: ?[]const u8 = null,
    scheme: ?[]const u8 = null,
    authority: ?[]const u8 = null,
    body: ?[]const u8 = null,
};

/// Parse HTTP/3 frames and decode request
pub fn decodeRequest(stream_data: []const u8, allocator: std.mem.Allocator) !DecodedRequest {
    var decoded = DecodedRequest{};
    var offset: usize = 0;

    while (offset < stream_data.len) {
        // Parse frame header
        const result = try FrameHeader.parse(stream_data[offset..]);
        offset += result.consumed;

        const frame_len: usize = @intCast(result.header.length);
        if (stream_data.len < offset + frame_len) return error.BufferTooSmall;

        switch (result.header.frame_type) {
            .headers => {
                // Parse QPACK encoded headers
                const encoded_headers = stream_data[offset .. offset + frame_len];
                decoded = try parseQPackHeaders(encoded_headers, allocator);
            },
            .data => {
                // Extract body
                decoded.body = stream_data[offset .. offset + frame_len];
            },
            else => {
                // Skip unknown frame types
            },
        }

        offset += frame_len;
    }

    return decoded;
}

/// Parse QPACK encoded headers (simplified - literal only)
fn parseQPackHeaders(data: []const u8, allocator: std.mem.Allocator) !DecodedRequest {
    var decoded = DecodedRequest{};
    var offset: usize = 0;

    // Skip Required Insert Count (1 byte)
    if (data.len < 1) return error.BufferTooSmall;
    offset += 1;

    // Skip Base (1 byte)
    if (data.len < offset + 1) return error.BufferTooSmall;
    offset += 1;

    // Parse literal field lines
    while (offset < data.len) {
        // Check for literal field line (0x20 prefix)
        if (data[offset] != 0x20) return error.UnsupportedQPackEncoding;
        offset += 1;

        // Parse name length
        const name_len_varint = try quic.VarInt.parse(data[offset..]);
        offset += name_len_varint.length;
        const name_len: usize = @intCast(name_len_varint.value);

        if (data.len < offset + name_len) return error.BufferTooSmall;
        const name = data[offset .. offset + name_len];
        offset += name_len;

        // Parse value length
        const value_len_varint = try quic.VarInt.parse(data[offset..]);
        offset += value_len_varint.length;
        const value_len: usize = @intCast(value_len_varint.value);

        if (data.len < offset + value_len) return error.BufferTooSmall;
        const value = data[offset .. offset + value_len];
        offset += value_len;

        // Store the header based on name
        if (std.mem.eql(u8, name, ":method")) {
            decoded.method = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, name, ":path")) {
            decoded.path = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, name, ":scheme")) {
            decoded.scheme = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, name, ":authority")) {
            decoded.authority = try allocator.dupe(u8, value);
        }
    }

    return decoded;
}

/// Decoded HTTP/3 response
pub const DecodedResponse = struct {
    status: ?[]const u8 = null,
    body: ?[]const u8 = null,
};

/// Parse HTTP/3 frames and decode response
pub fn decodeResponse(stream_data: []const u8, allocator: std.mem.Allocator) !DecodedResponse {
    var decoded = DecodedResponse{};
    var offset: usize = 0;

    while (offset < stream_data.len) {
        // Parse frame header
        const result = try FrameHeader.parse(stream_data[offset..]);
        offset += result.consumed;

        const frame_len: usize = @intCast(result.header.length);
        if (stream_data.len < offset + frame_len) return error.BufferTooSmall;

        switch (result.header.frame_type) {
            .headers => {
                // Parse QPACK encoded headers
                const encoded_headers = stream_data[offset .. offset + frame_len];
                decoded = try parseQPackResponseHeaders(encoded_headers, allocator);
            },
            .data => {
                // Extract body
                decoded.body = stream_data[offset .. offset + frame_len];
            },
            else => {
                // Skip unknown frame types
            },
        }

        offset += frame_len;
    }

    return decoded;
}

/// Parse QPACK encoded response headers
fn parseQPackResponseHeaders(data: []const u8, allocator: std.mem.Allocator) !DecodedResponse {
    var decoded = DecodedResponse{};
    var offset: usize = 0;

    // Skip Required Insert Count (1 byte)
    if (data.len < 1) return error.BufferTooSmall;
    offset += 1;

    // Skip Base (1 byte)
    if (data.len < offset + 1) return error.BufferTooSmall;
    offset += 1;

    // Parse literal field lines
    while (offset < data.len) {
        // Check for literal field line (0x20 prefix)
        if (data[offset] != 0x20) return error.UnsupportedQPackEncoding;
        offset += 1;

        // Parse name length
        const name_len_varint = try quic.VarInt.parse(data[offset..]);
        offset += name_len_varint.length;
        const name_len: usize = @intCast(name_len_varint.value);

        if (data.len < offset + name_len) return error.BufferTooSmall;
        const name = data[offset .. offset + name_len];
        offset += name_len;

        // Parse value length
        const value_len_varint = try quic.VarInt.parse(data[offset..]);
        offset += value_len_varint.length;
        const value_len: usize = @intCast(value_len_varint.value);

        if (data.len < offset + value_len) return error.BufferTooSmall;
        const value = data[offset .. offset + value_len];
        offset += value_len;

        // Store the header based on name
        if (std.mem.eql(u8, name, ":status")) {
            decoded.status = try allocator.dupe(u8, value);
        }
    }

    return decoded;
}

/// HTTP/3 Request
pub const Request = struct {
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: []const u8,
    body: []const u8,

    /// Encode request as HTTP/3 frames on a QUIC stream
    pub fn encode(self: Request, stream_buf: []u8) !usize {
        var offset: usize = 0;

        // Encode HEADERS frame with pseudo-headers
        var qpack_buf: [1024]u8 = undefined;
        const headers = [_]Header{
            .{ .name = ":method", .value = self.method },
            .{ .name = ":path", .value = self.path },
            .{ .name = ":scheme", .value = self.scheme },
            .{ .name = ":authority", .value = self.authority },
        };

        const encoded_headers = try QPack.encodeLiteralHeaders(&headers, &qpack_buf);

        const headers_frame = HeadersFrame{ .encoded_field_section = encoded_headers };
        const headers_len = try headers_frame.serialize(stream_buf[offset..]);
        offset += headers_len;

        // Encode DATA frame with body (if present)
        if (self.body.len > 0) {
            const data_frame = DataFrame{ .data = self.body };
            const data_len = try data_frame.serialize(stream_buf[offset..]);
            offset += data_len;
        }

        return offset;
    }
};

/// HTTP/3 Response
pub const Response = struct {
    status: []const u8,
    body: []const u8,

    /// Encode response as HTTP/3 frames
    pub fn encode(self: Response, stream_buf: []u8) !usize {
        var offset: usize = 0;

        // Encode HEADERS frame with status
        var qpack_buf: [1024]u8 = undefined;
        const headers = [_]Header{
            .{ .name = ":status", .value = self.status },
        };

        const encoded_headers = try QPack.encodeLiteralHeaders(&headers, &qpack_buf);

        const headers_frame = HeadersFrame{ .encoded_field_section = encoded_headers };
        const headers_len = try headers_frame.serialize(stream_buf[offset..]);
        offset += headers_len;

        // Encode DATA frame with body
        if (self.body.len > 0) {
            const data_frame = DataFrame{ .data = self.body };
            const data_len = try data_frame.serialize(stream_buf[offset..]);
            offset += data_len;
        }

        return offset;
    }
};

test "HTTP/3 DATA frame serialization" {
    const data = "Hello, World!";
    const frame = DataFrame{ .data = data };

    var buf: [100]u8 = undefined;
    _ = try frame.serialize(&buf);

    // Verify frame type (DATA = 0x00)
    try std.testing.expectEqual(@as(u8, 0x00), buf[0]);

    // Verify frame length (13 bytes)
    try std.testing.expectEqual(@as(u8, 13), buf[1]);

    // Verify data
    try std.testing.expectEqualStrings("Hello, World!", buf[2 .. 2 + data.len]);
}

test "HTTP/3 HEADERS frame serialization" {
    const encoded = "test headers";
    const frame = HeadersFrame{ .encoded_field_section = encoded };

    var buf: [100]u8 = undefined;
    _ = try frame.serialize(&buf);

    // Verify frame type (HEADERS = 0x01)
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);

    // Verify frame length
    try std.testing.expectEqual(@as(u8, 12), buf[1]);
}

test "HTTP/3 Request encoding" {
    const request = Request{
        .method = "GET",
        .path = "/",
        .scheme = "https",
        .authority = "example.com",
        .body = "Hello, World!",
    };

    var buf: [1024]u8 = undefined;
    const len = try request.encode(&buf);

    // Should have HEADERS frame followed by DATA frame
    try std.testing.expect(len > 0);

    // First frame should be HEADERS (0x01)
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);
}

/// Parsed HTTP/3 request data
pub const ParsedRequest = struct {
    stream_id: u64,
    offset: u64,
    body: []const u8,
    fin: bool,
};

/// Parse HTTP/3 request from QUIC packet payload
/// Returns the parsed request data or an error
pub fn parseRequest(payload: []const u8) !ParsedRequest {
    // Parse STREAM frame from QUIC payload
    const stream_frame = StreamFrame.parse(payload) catch |err| {
        std.debug.print("Failed to parse STREAM frame: {}\n", .{err});
        return err;
    };

    std.debug.print("Parsed STREAM frame: stream_id={d}, offset={d}, data_len={d}, fin={}\n", .{
        stream_frame.stream_id,
        stream_frame.offset,
        stream_frame.data.len,
        stream_frame.fin,
    });

    // Parse HTTP/3 frames and extract body
    const body = parseHttp3Body(stream_frame.data) catch |err| {
        std.debug.print("Failed to parse HTTP/3 body: {}\n", .{err});
        return err;
    };

    return ParsedRequest{
        .stream_id = stream_frame.stream_id,
        .offset = stream_frame.offset,
        .body = body,
        .fin = stream_frame.fin,
    };
}

/// Default HTTP/3 packet handler for QUIC server
/// This handler parses QUIC packets containing HTTP/3 frames and extracts the request body
pub fn http3Handle(packet: quic.Packet, src: std.net.Address) void {
    var src_buf: [128]u8 = undefined;
    const src_str = format.formatAddress(src, &src_buf) catch "unknown";
    std.debug.print("Received packet from {s}\n", .{src_str});

    const payload = packet.getPayload();
    const packet_type = packet.getPacketType();

    std.debug.print("Packet type: {s}, payload size: {d} bytes\n", .{ @tagName(packet_type), payload.len });

    // Parse HTTP/3 request using shared parsing logic
    const request = parseRequest(payload) catch {
        return;
    };

    std.debug.print("HTTP/3 Request Body: \"{s}\"\n", .{request.body});
}
