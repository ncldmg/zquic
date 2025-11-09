const std = @import("std");

/// Format an IPv4 or IPv6 address with port into a human-readable string
/// Returns a slice of the buffer containing the formatted address
pub fn formatAddress(addr: std.net.Address, buf: []u8) ![]const u8 {
    return switch (addr.any.family) {
        std.posix.AF.INET => formatIpv4(addr, buf),
        std.posix.AF.INET6 => formatIpv6(addr, buf),
        else => std.fmt.bufPrint(buf, "unknown", .{}),
    };
}

/// Format an IPv4 address as "a.b.c.d:port"
pub fn formatIpv4(addr: std.net.Address, buf: []u8) ![]const u8 {
    const ip = addr.in.sa.addr;
    const a = @as(u8, @intCast((ip >> 0) & 0xFF));
    const b = @as(u8, @intCast((ip >> 8) & 0xFF));
    const c = @as(u8, @intCast((ip >> 16) & 0xFF));
    const d = @as(u8, @intCast((ip >> 24) & 0xFF));
    const port = addr.getPort();

    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}:{d}", .{ a, b, c, d, port });
}

/// Format an IPv6 address as "[xxxx:xxxx:...:xxxx]:port"
/// Implements RFC 5952 formatting (compress longest run of zeros with ::)
pub fn formatIpv6(addr: std.net.Address, buf: []u8) ![]const u8 {
    const ipv6_addr = addr.in6.sa.addr;
    const port = addr.getPort();

    // Convert byte array to 16-bit groups (big-endian)
    var groups: [8]u16 = undefined;
    for (0..8) |i| {
        groups[i] = (@as(u16, ipv6_addr[i * 2]) << 8) | @as(u16, ipv6_addr[i * 2 + 1]);
    }

    // Find longest sequence of zeros for compression
    var longest_zero_start: ?usize = null;
    var longest_zero_len: usize = 0;
    var current_zero_start: ?usize = null;
    var current_zero_len: usize = 0;

    for (groups, 0..) |group, i| {
        if (group == 0) {
            if (current_zero_start == null) {
                current_zero_start = i;
                current_zero_len = 1;
            } else {
                current_zero_len += 1;
            }
        } else {
            if (current_zero_len > longest_zero_len and current_zero_len > 1) {
                longest_zero_start = current_zero_start;
                longest_zero_len = current_zero_len;
            }
            current_zero_start = null;
            current_zero_len = 0;
        }
    }

    // Check final sequence
    if (current_zero_len > longest_zero_len and current_zero_len > 1) {
        longest_zero_start = current_zero_start;
        longest_zero_len = current_zero_len;
    }

    // Format the address
    var offset: usize = 0;
    buf[offset] = '[';
    offset += 1;

    var i: usize = 0;
    while (i < 8) : (i += 1) {
        // Check if we're at the start of the compressed section
        if (longest_zero_start) |start| {
            if (i == start) {
                buf[offset] = ':';
                offset += 1;
                buf[offset] = ':';
                offset += 1;
                i += longest_zero_len;
                if (i >= 8) break;
            }
        }

        // Write the group
        const written = try std.fmt.bufPrint(buf[offset..], "{x}", .{groups[i]});
        offset += written.len;

        // Add separator if not last group
        if (i < 7 and (longest_zero_start == null or i + 1 != longest_zero_start.?)) {
            buf[offset] = ':';
            offset += 1;
        }
    }

    buf[offset] = ']';
    offset += 1;
    buf[offset] = ':';
    offset += 1;

    const port_written = try std.fmt.bufPrint(buf[offset..], "{d}", .{port});
    offset += port_written.len;

    return buf[0..offset];
}

test "format IPv4 address" {
    const addr = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 8080);
    var buf: [64]u8 = undefined;
    const formatted = try formatAddress(addr, &buf);
    try std.testing.expectEqualStrings("127.0.0.1:8080", formatted);
}

test "format IPv4 address different values" {
    const addr = std.net.Address.initIp4([4]u8{ 192, 168, 1, 100 }, 443);
    var buf: [64]u8 = undefined;
    const formatted = try formatAddress(addr, &buf);
    try std.testing.expectEqualStrings("192.168.1.100:443", formatted);
}

test "format IPv6 address localhost" {
    const addr = std.net.Address.initIp6([16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 8080, 0, 0);
    var buf: [128]u8 = undefined;
    const formatted = try formatAddress(addr, &buf);
    try std.testing.expectEqualStrings("[::1]:8080", formatted);
}

test "format IPv6 address with compression" {
    const addr = std.net.Address.initIp6([16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 443, 0, 0);
    var buf: [128]u8 = undefined;
    const formatted = try formatAddress(addr, &buf);
    try std.testing.expectEqualStrings("[2001:db8::1]:443", formatted);
}

test "format IPv6 address no compression" {
    const addr = std.net.Address.initIp6([16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6 }, 9000, 0, 0);
    var buf: [128]u8 = undefined;
    const formatted = try formatAddress(addr, &buf);
    try std.testing.expectEqualStrings("[2001:db8:1:2:3:4:5:6]:9000", formatted);
}

test "format IPv6 all zeros" {
    const addr = std.net.Address.initIp6([16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 80, 0, 0);
    var buf: [128]u8 = undefined;
    const formatted = try formatAddress(addr, &buf);
    try std.testing.expectEqualStrings("[::]:80", formatted);
}
