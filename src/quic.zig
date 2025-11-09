const std = @import("std");

/// QUIC Protocol Implementation
/// Based on RFC 9000
/// QUIC packet types
pub const PacketType = enum(u8) {
    /// Initial packet - First packet in QUIC handshake, contains Client Hello
    /// Must be padded to at least 1200 bytes to help with PMTU discovery
    initial = 0x00,

    /// 0-RTT packet - Early application data sent during connection resumption
    /// Contains application data before handshake completes (not guaranteed to be accepted)
    zero_rtt = 0x01,

    /// Handshake packet - Contains TLS handshake messages (CRYPTO frames)
    /// Used to complete the TLS 1.3 handshake after Initial packet exchange
    handshake = 0x02,

    /// Retry packet - Server sends to validate client address and provide token
    /// Used for Denial of Service mitigation and address validation
    retry = 0x03,

    /// Version Negotiation packet - Server response when version is not supported
    /// Contains list of versions supported by the server
    version_negotiation = 0xfe,

    /// Short Header packet (1-RTT) - Normal application data after handshake completes
    /// Most packets in an established QUIC connection use this type
    /// Special internal value (not a wire format value)
    short_header = 0xff,

    pub fn fromByte(byte: u8, is_long_header: bool) !PacketType {
        if (!is_long_header) {
            return .short_header;
        }

        // Long header: extract type from bits 4-5
        const type_bits = (byte >> 4) & 0x03;
        return switch (type_bits) {
            0x00 => .initial,
            0x01 => .zero_rtt,
            0x02 => .handshake,
            0x03 => .retry,
            else => error.InvalidPacketType,
        };
    }
};

/// QUIC version (RFC 9000 = version 1)
pub const Version = enum(u32) {
    version_1 = 0x00000001,
    version_negotiation = 0x00000000,

    pub fn fromU32(value: u32) Version {
        return switch (value) {
            0x00000001 => .version_1,
            0x00000000 => .version_negotiation,
            else => @enumFromInt(value),
        };
    }
};

// QUIC protocol constants (RFC 9000)
const max_connection_id_len: u8 = 20; // Maximum Connection ID length (Section 17.2)

/// Connection ID (variable length, 0-20 bytes)
pub const ConnectionId = struct {
    data: [max_connection_id_len]u8 = undefined,
    len: u8 = 0,

    pub fn isEmpty(self: ConnectionId) bool {
        return self.len == 0;
    }

    pub fn slice(self: ConnectionId) []const u8 {
        return self.data[0..self.len];
    }

    /// Format connection ID as hex string
    pub fn toHexString(self: ConnectionId, buf: []u8) ![]const u8 {
        if (buf.len < self.len * 2 + 2) return error.BufferTooSmall;

        buf[0] = '0';
        buf[1] = 'x';

        const hex_digits = "0123456789abcdef";
        var offset: usize = 2;
        for (self.slice()) |byte| {
            buf[offset] = hex_digits[byte >> 4];
            buf[offset + 1] = hex_digits[byte & 0x0f];
            offset += 2;
        }

        return buf[0..offset];
    }
};

/// Long Header Packet - Used during connection establishment and handshake
///
/// Long headers are used for Initial, 0-RTT, Handshake, and Retry packets.
/// They contain additional fields needed for connection establishment:
/// - version: Allows version negotiation between client and server
/// - scid: Source Connection ID needed to establish bidirectional communication
/// - token: Address validation token (Initial packets only, for DoS mitigation)
/// - length: Explicit payload length (required when packets are padded to minimum size)
///
/// Typical size: 20-50 bytes header overhead (larger than Short Header)
/// Used for: Connection setup, TLS handshake, version negotiation, address validation
pub const LongHeader = struct {
    packet_type: PacketType,
    version: Version,
    dcid: ConnectionId, // Destination Connection ID
    scid: ConnectionId, // Source Connection ID
    token: ?[]const u8 = null, // Initial packets only
    length: u64, // Payload length
    packet_number: u32,
    payload: []const u8,
};

/// Short Header Packet (1-RTT) - Used for application data after handshake completes
///
/// Short headers are optimized for minimal overhead during normal data transfer.
/// They omit fields that are only needed during connection establishment:
/// - No version field (already negotiated during handshake)
/// - No scid field (both endpoints already know each other's Connection IDs)
/// - No token field (connection already established and validated)
/// - No length field (implicit from UDP datagram length)
///
/// Typical size: 5-20 bytes header overhead (minimal overhead for efficiency)
/// Used for: All application data after the handshake completes (majority of packets)
/// Benefit: ~15-30 bytes smaller than Long Header, improving bandwidth efficiency
pub const ShortHeader = struct {
    dcid: ConnectionId,
    packet_number: u32,
    payload: []const u8,
};

/// Parsed QUIC packet
pub const Packet = union(enum) {
    long_header: LongHeader,
    short_header: ShortHeader,

    pub fn getPayload(self: Packet) []const u8 {
        return switch (self) {
            .long_header => |h| h.payload,
            .short_header => |h| h.payload,
        };
    }

    pub fn getPacketType(self: Packet) PacketType {
        return switch (self) {
            .long_header => |h| h.packet_type,
            .short_header => .short_header,
        };
    }
};

/// Variable-Length Integer (RFC 9000 Section 16)
///
/// VarInt is a space-efficient encoding that uses 1, 2, 4, or 8 bytes depending on the value.
/// This saves bandwidth compared to always using 8 bytes for every integer.
///
/// ENCODING FORMAT:
/// The first 2 bits of the first byte indicate the total length:
///   00xxxxxx = 1 byte  (values 0-63)           →  6 bits for value
///   01xxxxxx = 2 bytes (values 0-16,383)       → 14 bits for value
///   10xxxxxx = 4 bytes (values 0-1,073,741,823)→ 30 bits for value
///   11xxxxxx = 8 bytes (values 0-4,611,686,018,427,387,903) → 62 bits for value
///
/// EXAMPLES:
///   Value 37:
///     Binary: 00100101
///     Encoded as: [0x25] (1 byte)
///     First 2 bits (00) → length=1, remaining 6 bits (100101) → value=37
///
///   Value 15,000:
///     Binary: 0011101010011000
///     Encoded as: [0x7A, 0x98] (2 bytes)
///     First byte: 01111010 → First 2 bits (01) → length=2, remaining bits contribute to value
///     Combined: (0x3A << 8) | 0x98 = 15,000
///
/// WHY USE VARINT:
///   - Packet numbers start small (0, 1, 2...) → use 1 byte instead of 4
///   - Stream IDs start small → save 3-7 bytes per frame
///   - Most payload lengths < 16,384 → use 2 bytes instead of 8
///   - Saves significant bandwidth over time (millions of packets)

// VarInt encoding constants
const value_mask: u8 = 0x3f; // 0b00111111 - Mask for bottom 6 bits (value bits)
const byte_mask: u8 = 0xff; // 0b11111111 - Mask for extracting a single byte
const two_byte_prefix: u8 = 0x40; // 0b01000000 - 2-byte encoding prefix
const four_byte_prefix: u8 = 0x80; // 0b10000000 - 4-byte encoding prefix
const eight_byte_prefix: u8 = 0xc0; // 0b11000000 - 8-byte encoding prefix

// Value range limits for each encoding
const max_one_byte: u64 = 64; // 2^6
const max_two_byte: u64 = 16384; // 2^14
const max_four_byte: u64 = 1073741824; // 2^30
// max_eight_byte = 2^62 (implicit)

// VarInt length constants
const varint_len_1: usize = 1;
const varint_len_2: usize = 2;
const varint_len_4: usize = 4;
const varint_len_8: usize = 8;

// Bit shift amounts
const bits_per_byte: u6 = 8;

// Short Header packet constants (RFC 9000 Section 17.3)
const pn_length_mask: u8 = 0x03; // 0b00000011 - Mask for bits 0-1 (packet number length)
const pn_length_offset: u8 = 1; // Add 1 to convert 0-3 to actual length 1-4 bytes
const default_dcid_len: u8 = 8; // Default DCID length for short header (implementation-specific)

// Long Header packet constants (RFC 9000 Section 17.2)
const min_long_header_size: usize = 6; // Minimum bytes for long header (1 + 4 version + 1 dcid_len)
const version_field_size: usize = 4; // Version field is 4 bytes
const pn_length_mask_long: u8 = 0x03; // Mask for bits 0-1 (packet number length in long header)

pub const VarInt = struct {
    value: u64,
    length: usize, // Number of bytes consumed from the buffer

    /// Parse variable-length integer from buffer
    ///
    /// ALGORITHM:
    /// 1. Read first byte
    /// 2. Extract top 2 bits (length_bits = first_byte >> 6)
    /// 3. Use length_bits to determine how many total bytes to read
    /// 4. Mask out the length bits (first_byte & 0x3f) to get value bits
    /// 5. Combine remaining bytes using bit shifting
    pub fn parse(data: []const u8) !VarInt {
        if (data.len == 0) return error.BufferTooSmall;

        const first_byte = data[0];
        // Extract top 2 bits to determine length
        // Example: 0b01101010 >> 6 = 0b00000001 = 1 (means 2-byte encoding)
        const length_bits = first_byte >> 6;

        return switch (length_bits) {
            // 1-byte encoding: 00xxxxxx
            // Value range: 0-63 (2^6 - 1)
            // Example: 0x25 (00100101) → value = 0x25 & value_mask = 37
            0 => VarInt{
                .value = first_byte & value_mask, // Keep bottom 6 bits
                .length = varint_len_1,
            },

            // 2-byte encoding: 01xxxxxx xxxxxxxx
            // Value range: 0-16,383 (2^14 - 1)
            // Example: [0x7A, 0x98] → value = (0x3A << 8) | 0x98 = 15,000
            //   Step 1: first_byte & value_mask = 0x7A & 0x3F = 0x3A (mask out top 2 bits)
            //   Step 2: 0x3A << 8 = 0x3A00 (shift left to make room for second byte)
            //   Step 3: 0x3A00 | 0x98 = 0x3A98 = 15,000
            1 => blk: {
                if (data.len < varint_len_2) return error.BufferTooSmall;
                const value = (@as(u64, first_byte & value_mask) << bits_per_byte) | data[1];
                break :blk VarInt{ .value = value, .length = varint_len_2 };
            },

            // 4-byte encoding: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
            // Value range: 0-1,073,741,823 (2^30 - 1)
            // Process: Take 6 bits from first byte, then 8 bits from each of 3 remaining bytes
            //   value = (byte0 & value_mask) << 24 | byte1 << 16 | byte2 << 8 | byte3
            2 => blk: {
                if (data.len < varint_len_4) return error.BufferTooSmall;
                var value: u64 = first_byte & value_mask;
                value = (value << bits_per_byte) | data[1]; // Shift and add byte 1
                value = (value << bits_per_byte) | data[2]; // Shift and add byte 2
                value = (value << bits_per_byte) | data[3]; // Shift and add byte 3
                break :blk VarInt{ .value = value, .length = varint_len_4 };
            },

            // 8-byte encoding: 11xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
            // Value range: 0-4,611,686,018,427,387,903 (2^62 - 1)
            // Process: Take 6 bits from first byte, then 8 bits from each of 7 remaining bytes
            3 => blk: {
                if (data.len < varint_len_8) return error.BufferTooSmall;
                var value: u64 = first_byte & value_mask;
                for (data[1..varint_len_8]) |byte| {
                    value = (value << bits_per_byte) | byte; // Shift and add each byte
                }
                break :blk VarInt{ .value = value, .length = varint_len_8 };
            },

            else => unreachable,
        };
    }

    /// Encode variable-length integer to buffer
    ///
    /// ALGORITHM:
    /// 1. Determine minimum bytes needed based on value
    /// 2. Set appropriate length bits (00, 01, 10, or 11) in first byte
    /// 3. Write value bytes in big-endian order
    pub fn encode(value: u64, buf: []u8) !usize {
        // 1-byte encoding: values 0-63
        // Format: 00xxxxxx
        // Example: 37 → 0x25 (00100101)
        if (value < max_one_byte) {
            if (buf.len < varint_len_1) return error.BufferTooSmall;
            buf[0] = @intCast(value); // Top 2 bits already 00
            return varint_len_1;
        }
        // 2-byte encoding: values 64-16,383
        // Format: 01xxxxxx xxxxxxxx
        // Example: 15,000 → [0x7A, 0x98]
        //   15,000 = 0x3A98
        //   buf[0] = two_byte_prefix | (0x3A98 >> 8) = 0x40 | 0x3A = 0x7A (set top bits to 01)
        //   buf[1] = 0x3A98 & 0xFF = 0x98
        else if (value < max_two_byte) {
            if (buf.len < varint_len_2) return error.BufferTooSmall;
            buf[0] = @intCast(two_byte_prefix | (value >> bits_per_byte)); // Set length bits to 01
            buf[1] = @intCast(value & byte_mask);
            return varint_len_2;
        }
        // 4-byte encoding: values 16,384-1,073,741,823
        // Format: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        else if (value < max_four_byte) {
            if (buf.len < varint_len_4) return error.BufferTooSmall;
            buf[0] = @intCast(four_byte_prefix | (value >> (bits_per_byte * 3))); // Set top bits to 10
            buf[1] = @intCast((value >> (bits_per_byte * 2)) & byte_mask);
            buf[2] = @intCast((value >> bits_per_byte) & byte_mask);
            buf[3] = @intCast(value & byte_mask);
            return varint_len_4;
        }
        // 8-byte encoding: values 1,073,741,824+
        // Format: 11xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        else {
            if (buf.len < varint_len_8) return error.BufferTooSmall;
            buf[0] = @intCast(eight_byte_prefix | (value >> (bits_per_byte * 7))); // Set top bits to 11
            for (1..varint_len_8) |i| {
                buf[i] = @intCast((value >> @intCast((7 - i) * bits_per_byte)) & byte_mask);
            }
            return varint_len_8;
        }
    }
};

/// QUIC Packet Parser
pub const Parser = struct {
    /// Parse a QUIC packet from raw UDP datagram
    pub fn parse(data: []const u8) !Packet {
        if (data.len == 0) return error.EmptyPacket;

        const first_byte = data[0];

        // Check if long header (bit 7 set)
        const is_long_header = (first_byte & four_byte_prefix) != 0;

        if (is_long_header) {
            return Packet{ .long_header = try parseLongHeader(data) };
        } else {
            return Packet{ .short_header = try parseShortHeader(data) };
        }
    }

    /// Parse Long Header packet
    fn parseLongHeader(data: []const u8) !LongHeader {
        if (data.len < min_long_header_size) return error.PacketTooSmall;

        var offset: usize = 0;
        const first_byte = data[offset];
        offset += 1;

        // Parse packet type
        const packet_type = try PacketType.fromByte(first_byte, true);

        // Parse version (4 bytes)
        if (data.len < offset + version_field_size) return error.PacketTooSmall;
        const version_bytes = data[offset .. offset + version_field_size];
        const version_value = std.mem.readInt(u32, version_bytes[0..version_field_size], .big);
        const version = Version.fromU32(version_value);
        offset += version_field_size;

        // Parse DCID length and value
        if (data.len < offset + 1) return error.PacketTooSmall;
        const dcid_len = data[offset];
        offset += 1;

        if (dcid_len > max_connection_id_len) return error.InvalidConnectionIdLength;
        if (data.len < offset + dcid_len) return error.PacketTooSmall;

        var dcid = ConnectionId{};
        dcid.len = dcid_len;
        if (dcid_len > 0) {
            @memcpy(dcid.data[0..dcid_len], data[offset .. offset + dcid_len]);
        }
        offset += dcid_len;

        // Parse SCID length and value
        if (data.len < offset + 1) return error.PacketTooSmall;
        const scid_len = data[offset];
        offset += 1;

        if (scid_len > max_connection_id_len) return error.InvalidConnectionIdLength;
        if (data.len < offset + scid_len) return error.PacketTooSmall;

        var scid = ConnectionId{};
        scid.len = scid_len;
        if (scid_len > 0) {
            @memcpy(scid.data[0..scid_len], data[offset .. offset + scid_len]);
        }
        offset += scid_len;

        // Parse token (Initial packets only)
        var token: ?[]const u8 = null;
        if (packet_type == .initial) {
            const token_length_varint = try VarInt.parse(data[offset..]);
            offset += token_length_varint.length;

            if (token_length_varint.value > 0) {
                const token_len: usize = @intCast(token_length_varint.value);
                if (data.len < offset + token_len) return error.PacketTooSmall;
                token = data[offset .. offset + token_len];
                offset += token_len;
            }
        }

        // Parse length (variable-length integer)
        const length_varint = try VarInt.parse(data[offset..]);
        offset += length_varint.length;

        const payload_length: usize = @intCast(length_varint.value);
        if (data.len < offset + payload_length) return error.PacketTooSmall;

        // Extract packet number length from first byte bits 0-1 (RFC 9000 Section 17.2)
        // Bits 0-1 encode length as: 00=1 byte, 01=2 bytes, 10=3 bytes, 11=4 bytes
        const pn_length = (first_byte & pn_length_mask_long) + pn_length_offset;
        if (payload_length < pn_length) return error.PacketTooSmall;

        // Parse packet number (variable length 1-4 bytes)
        var packet_number: u32 = 0;
        for (0..pn_length) |i| {
            packet_number = (packet_number << bits_per_byte) | data[offset + i];
        }
        offset += pn_length;

        // Remaining data is payload (after packet number)
        const payload = data[offset .. offset + payload_length - pn_length];

        return LongHeader{
            .packet_type = packet_type,
            .version = version,
            .dcid = dcid,
            .scid = scid,
            .token = token,
            .length = length_varint.value,
            .packet_number = packet_number,
            .payload = payload,
        };
    }

    /// Parse Short Header packet (1-RTT)
    fn parseShortHeader(data: []const u8) !ShortHeader {
        if (data.len < 2) return error.PacketTooSmall;

        var offset: usize = 0;
        const first_byte = data[offset];
        offset += 1;

        // Extract packet number length from bits 0-1 (RFC 9000 Section 17.3)
        // Bits 0-1 encode length as: 00=1 byte, 01=2 bytes, 10=3 bytes, 11=4 bytes
        const pn_length = (first_byte & pn_length_mask) + pn_length_offset;

        // Note: In a real implementation, DCID length is determined by
        // connection state. Here we assume it's encoded somehow or
        // we use a fixed length for demonstration.
        // For simplicity, we'll assume default_dcid_len byte DCID
        const dcid_len = default_dcid_len;

        if (data.len < offset + dcid_len) return error.PacketTooSmall;

        var dcid = ConnectionId{};
        dcid.len = dcid_len;
        @memcpy(dcid.data[0..dcid_len], data[offset .. offset + dcid_len]);
        offset += dcid_len;

        // Parse packet number
        if (data.len < offset + pn_length) return error.PacketTooSmall;

        var packet_number: u32 = 0;
        for (0..pn_length) |i| {
            packet_number = (packet_number << bits_per_byte) | data[offset + i];
        }
        offset += pn_length;

        // Remaining data is encrypted payload
        const payload = data[offset..];

        return ShortHeader{
            .dcid = dcid,
            .packet_number = packet_number,
            .payload = payload,
        };
    }
};

/// QUIC Packet Encoder
pub const Encoder = struct {
    /// Encode a Long Header packet
    pub fn encodeLongHeader(header: LongHeader, buf: []u8) !usize {
        var offset: usize = 0;

        // First byte: 1 (long header) | 1 (fixed bit) | packet_type (2 bits) | packet_number_length (2 bits) | reserved (2 bits)
        // Packet number length encoding: 00=1 byte, 01=2 bytes, 10=3 bytes, 11=4 bytes
        const pn_length: u8 = switch (header.packet_number) {
            0...0xFF => 1,
            0x100...0xFFFF => 2,
            0x10000...0xFFFFFF => 3,
            else => 4,
        };
        const pn_length_bits: u8 = pn_length - 1; // Convert 1-4 to 0-3

        const type_bits: u8 = switch (header.packet_type) {
            .initial => 0x00,
            .zero_rtt => 0x01,
            .handshake => 0x02,
            .retry => 0x03,
            else => return error.InvalidPacketType,
        };

        buf[offset] = 0xc0 | (type_bits << 4) | pn_length_bits;
        offset += 1;

        // Version (4 bytes, big-endian)
        std.mem.writeInt(u32, buf[offset..][0..4], @intFromEnum(header.version), .big);
        offset += 4;

        // DCID length and value
        buf[offset] = header.dcid.len;
        offset += 1;
        if (header.dcid.len > 0) {
            @memcpy(buf[offset .. offset + header.dcid.len], header.dcid.slice());
            offset += header.dcid.len;
        }

        // SCID length and value
        buf[offset] = header.scid.len;
        offset += 1;
        if (header.scid.len > 0) {
            @memcpy(buf[offset .. offset + header.scid.len], header.scid.slice());
            offset += header.scid.len;
        }

        // Token (Initial packets only)
        if (header.packet_type == .initial) {
            const token_len = if (header.token) |t| t.len else 0;
            const token_len_encoded = try VarInt.encode(token_len, buf[offset..]);
            offset += token_len_encoded;

            if (header.token) |token| {
                @memcpy(buf[offset .. offset + token.len], token);
                offset += token.len;
            }
        }

        // Calculate payload length (packet number + payload)
        const total_payload_length = pn_length + header.payload.len;
        const length_encoded = try VarInt.encode(total_payload_length, buf[offset..]);
        offset += length_encoded;

        // Packet number (variable length 1-4 bytes, big-endian)
        for (0..pn_length) |i| {
            const shift = @as(u5, @intCast((pn_length - 1 - i) * 8));
            buf[offset + i] = @intCast((header.packet_number >> shift) & 0xFF);
        }
        offset += pn_length;

        // Payload
        @memcpy(buf[offset .. offset + header.payload.len], header.payload);
        offset += header.payload.len;

        return offset;
    }

    /// Encode a Short Header packet
    pub fn encodeShortHeader(header: ShortHeader, buf: []u8) !usize {
        var offset: usize = 0;

        // First byte: 0 (short header) | 1 (fixed bit) | spin bit | reserved (2) | key phase | packet_number_length (2)
        const pn_length: u8 = switch (header.packet_number) {
            0...0xFF => 1,
            0x100...0xFFFF => 2,
            0x10000...0xFFFFFF => 3,
            else => 4,
        };
        const pn_length_bits: u8 = pn_length - 1;

        buf[offset] = 0x40 | pn_length_bits; // 01000000 | pn_length_bits
        offset += 1;

        // DCID
        @memcpy(buf[offset .. offset + header.dcid.len], header.dcid.slice());
        offset += header.dcid.len;

        // Packet number
        for (0..pn_length) |i| {
            const shift = @as(u5, @intCast((pn_length - 1 - i) * 8));
            buf[offset + i] = @intCast((header.packet_number >> shift) & 0xFF);
        }
        offset += pn_length;

        // Payload
        @memcpy(buf[offset .. offset + header.payload.len], header.payload);
        offset += header.payload.len;

        return offset;
    }
};

/// QUIC Frame Types (RFC 9000 Section 12.4)
pub const FrameType = enum(u8) {
    padding = 0x00,
    ping = 0x01,
    ack = 0x02,
    ack_ecn = 0x03,
    reset_stream = 0x04,
    stop_sending = 0x05,
    crypto = 0x06,
    new_token = 0x07,
    stream = 0x08, // 0x08-0x0f (with flags)
    max_data = 0x10,
    max_stream_data = 0x11,
    max_streams_bidi = 0x12,
    max_streams_uni = 0x13,
    data_blocked = 0x14,
    stream_data_blocked = 0x15,
    streams_blocked_bidi = 0x16,
    streams_blocked_uni = 0x17,
    new_connection_id = 0x18,
    retire_connection_id = 0x19,
    path_challenge = 0x1a,
    path_response = 0x1b,
    connection_close = 0x1c,
    connection_close_app = 0x1d,
    handshake_done = 0x1e,
    _,

    pub fn fromByte(byte: u8) FrameType {
        // STREAM frames are 0x08-0x0f
        if (byte >= 0x08 and byte <= 0x0f) {
            return .stream;
        }
        return @enumFromInt(byte);
    }
};

/// QUIC Frame
pub const Frame = union(FrameType) {
    padding: void,
    ping: void,
    ack: AckFrame,
    ack_ecn: AckFrame,
    reset_stream: ResetStreamFrame,
    stop_sending: StopSendingFrame,
    crypto: CryptoFrame,
    new_token: NewTokenFrame,
    stream: StreamFrame,
    max_data: MaxDataFrame,
    max_stream_data: MaxStreamDataFrame,
    max_streams_bidi: MaxStreamsFrame,
    max_streams_uni: MaxStreamsFrame,
    data_blocked: DataBlockedFrame,
    stream_data_blocked: StreamDataBlockedFrame,
    streams_blocked_bidi: StreamsBlockedFrame,
    streams_blocked_uni: StreamsBlockedFrame,
    new_connection_id: NewConnectionIdFrame,
    retire_connection_id: RetireConnectionIdFrame,
    path_challenge: PathChallengeFrame,
    path_response: PathResponseFrame,
    connection_close: ConnectionCloseFrame,
    connection_close_app: ConnectionCloseFrame,
    handshake_done: void,
};

/// ACK Frame
pub const AckFrame = struct {
    largest_acknowledged: u64,
    ack_delay: u64,
    ack_ranges: []AckRange,
};

pub const AckRange = struct {
    gap: u64,
    length: u64,
};

/// CRYPTO Frame
pub const CryptoFrame = struct {
    offset: u64,
    length: u64,
    data: []const u8,
};

/// STREAM Frame
pub const StreamFrame = struct {
    stream_id: u64,
    offset: u64,
    length: u64,
    data: []const u8,
    fin: bool,

    /// Encode STREAM frame (RFC 9000 Section 19.8)
    pub fn encode(self: StreamFrame, buf: []u8) !usize {
        var offset: usize = 0;

        // STREAM frame type byte: 0x08 | OFF | LEN | FIN
        // OFF (0x04): offset field present
        // LEN (0x02): length field present
        // FIN (0x01): final frame of stream
        var frame_type: u8 = 0x08;
        if (self.offset > 0) frame_type |= 0x04;
        if (self.length > 0) frame_type |= 0x02;
        if (self.fin) frame_type |= 0x01;

        buf[offset] = frame_type;
        offset += 1;

        // Stream ID (variable-length integer)
        const stream_id_len = try VarInt.encode(self.stream_id, buf[offset..]);
        offset += stream_id_len;

        // Offset (if present)
        if (self.offset > 0) {
            const offset_len = try VarInt.encode(self.offset, buf[offset..]);
            offset += offset_len;
        }

        // Length (if present)
        if (self.length > 0) {
            const length_len = try VarInt.encode(self.length, buf[offset..]);
            offset += length_len;
        }

        // Stream data
        @memcpy(buf[offset .. offset + self.data.len], self.data);
        offset += self.data.len;

        return offset;
    }
};

/// Connection Close Frame
pub const ConnectionCloseFrame = struct {
    error_code: u64,
    frame_type: u64,
    reason_phrase: []const u8,
};

/// Other frame types (simplified)
pub const ResetStreamFrame = struct {
    stream_id: u64,
    error_code: u64,
    final_size: u64,
};

pub const StopSendingFrame = struct {
    stream_id: u64,
    error_code: u64,
};

pub const NewTokenFrame = struct {
    token: []const u8,
};

pub const MaxDataFrame = struct {
    maximum_data: u64,
};

pub const MaxStreamDataFrame = struct {
    stream_id: u64,
    maximum_stream_data: u64,
};

pub const MaxStreamsFrame = struct {
    maximum_streams: u64,
};

pub const DataBlockedFrame = struct {
    maximum_data: u64,
};

pub const StreamDataBlockedFrame = struct {
    stream_id: u64,
    maximum_stream_data: u64,
};

pub const StreamsBlockedFrame = struct {
    maximum_streams: u64,
};

pub const NewConnectionIdFrame = struct {
    sequence_number: u64,
    retire_prior_to: u64,
    connection_id: ConnectionId,
    stateless_reset_token: [16]u8,
};

pub const RetireConnectionIdFrame = struct {
    sequence_number: u64,
};

pub const PathChallengeFrame = struct {
    data: [8]u8,
};

pub const PathResponseFrame = struct {
    data: [8]u8,
};

// Tests
test "VarInt parsing" {
    // 1-byte encoding (value < 64)
    {
        const data = [_]u8{0x25}; // Value = 37
        const varint = try VarInt.parse(&data);
        try std.testing.expectEqual(@as(u64, 37), varint.value);
        try std.testing.expectEqual(@as(usize, 1), varint.length);
    }

    // 2-byte encoding (value < 16384)
    {
        const data = [_]u8{ 0x7b, 0xbd }; // Value = 15293
        const varint = try VarInt.parse(&data);
        try std.testing.expectEqual(@as(u64, 15293), varint.value);
        try std.testing.expectEqual(@as(usize, 2), varint.length);
    }

    // 4-byte encoding
    {
        const data = [_]u8{ 0x9d, 0x7f, 0x3e, 0x7d }; // Value = 494878333
        const varint = try VarInt.parse(&data);
        try std.testing.expectEqual(@as(u64, 494878333), varint.value);
        try std.testing.expectEqual(@as(usize, 4), varint.length);
    }
}

test "VarInt encoding" {
    var buf: [8]u8 = undefined;

    // 1-byte
    {
        const len = try VarInt.encode(37, &buf);
        try std.testing.expectEqual(@as(usize, 1), len);
        try std.testing.expectEqual(@as(u8, 0x25), buf[0]);
    }

    // 2-byte
    {
        const len = try VarInt.encode(15293, &buf);
        try std.testing.expectEqual(@as(usize, 2), len);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x7b, 0xbd }, buf[0..len]);
    }
}

test "Parse QUIC Initial packet" {
    // Simplified Initial packet (not a real one, but demonstrates structure)
    var packet_data = [_]u8{
        0xc0, // Long header, Initial packet
        0x00, 0x00, 0x00, 0x01, // Version 1
        0x08, // DCID length = 8
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
        0x00, // SCID length = 0
        0x00, // Token length = 0
        0x40, 0x10, // Length = 16 (2-byte varint)
        0x00, 0x00, 0x00, 0x01, // Packet number
        // Payload (12 bytes to match length - 4 for packet number)
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c,
    };

    const packet = try Parser.parse(&packet_data);

    try std.testing.expect(packet == .long_header);
    const header = packet.long_header;

    try std.testing.expectEqual(PacketType.initial, header.packet_type);
    try std.testing.expectEqual(Version.version_1, header.version);
    try std.testing.expectEqual(@as(u8, 8), header.dcid.len);
    try std.testing.expectEqual(@as(u8, 0), header.scid.len);
    try std.testing.expectEqual(@as(u32, 1), header.packet_number);
    try std.testing.expectEqual(@as(usize, 12), header.payload.len);
}

test "Parse QUIC Short Header packet" {
    // Simplified Short Header packet
    var packet_data = [_]u8{
        0x40, // Short header, 1-byte packet number
        // DCID (8 bytes, fixed for this test)
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x05, // Packet number
        // Payload
        0xaa,
        0xbb,
        0xcc,
        0xdd,
    };

    const packet = try Parser.parse(&packet_data);

    try std.testing.expect(packet == .short_header);
    const header = packet.short_header;

    try std.testing.expectEqual(@as(u8, 8), header.dcid.len);
    try std.testing.expectEqual(@as(u32, 5), header.packet_number);
    try std.testing.expectEqual(@as(usize, 4), header.payload.len);
}

test "ConnectionId formatting" {
    var cid = ConnectionId{};
    cid.len = 8;
    cid.data = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 } ++ [_]u8{0} ** 12;

    var buf: [100]u8 = undefined;
    const result = try cid.toHexString(&buf);
    try std.testing.expectEqualStrings("0x0102030405060708", result);
}
