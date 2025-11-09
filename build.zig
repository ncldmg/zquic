const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // -------------------------
    // Library Modules
    // -------------------------
    const format_mod = b.addModule("format", .{
        .root_source_file = b.path("src/format.zig"),
        .target = target,
    });

    const quic_mod = b.addModule("quic", .{
        .root_source_file = b.path("src/quic.zig"),
        .target = target,
    });

    const server_mod = b.addModule("server", .{
        .root_source_file = b.path("src/server.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "quic", .module = quic_mod },
            .{ .name = "format", .module = format_mod },
        },
    });

    const http3_mod = b.addModule("http3", .{
        .root_source_file = b.path("src/http3.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "quic", .module = quic_mod },
            .{ .name = "format", .module = format_mod },
        },
    });

    // -------------------------
    // CLI Dependency
    // -------------------------
    const cli_dep = b.dependency("cli", .{
        .target = target,
        .optimize = optimize,
    });
    const cli_mod = cli_dep.module("cli");

    // -------------------------
    // Executable
    // -------------------------
    const exe = b.addExecutable(.{
        .name = "zquic",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "format", .module = format_mod },
                .{ .name = "quic", .module = quic_mod },
                .{ .name = "server", .module = server_mod },
                .{ .name = "http3", .module = http3_mod },
                .{ .name = "cli", .module = cli_mod },
            },
        }),
    });
    b.installArtifact(exe);

    // -------------------------
    // Run step
    // -------------------------
    const run_step = b.step("run", "Run the zquic executable");
    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| run_cmd.addArgs(args);
    run_step.dependOn(&run_cmd.step);

    // -------------------------
    // Tests
    // -------------------------
    const exe_tests = b.addTest(.{ .root_module = exe.root_module });

    const http3_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/http3_integration_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "quic", .module = quic_mod },
                .{ .name = "http3", .module = http3_mod },
                .{ .name = "server", .module = server_mod },
            },
        }),
    });

    const test_step = b.step("test", "Run all tests with harness");
    test_step.dependOn(&exe_tests.step);
    test_step.dependOn(&http3_tests.step);

    const test_http3_step = b.step("test-http3", "Run only HTTP/3 integration tests");
    test_http3_step.dependOn(&http3_tests.step);

    const integration_step = b.step("integration", "Run HTTP/3 tests via harness");
    integration_step.dependOn(&http3_tests.step);
}
