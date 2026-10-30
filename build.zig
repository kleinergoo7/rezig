const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "rezig",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    const run_step = b.step("run", "Run the rezig CLI");
    run_step.dependOn(&run_cmd.step);

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);

    const opts = readOptions(b);
    addExtractStep(b, exe, opts);
    addAnalyzeStep(b, exe, opts);
    addUnlockStep(b, opts);
}

const Options = struct {
    iso: ?[]const u8,
    out: ?[]const u8,
    key: ?[]const u8,
    tree: ?[]const u8,
    xex: ?[]const u8,
    xextool: ?[]const u8,
};

/// Build options are global, so every step reads from this one table.
fn readOptions(b: *std.Build) Options {
    return .{
        .iso = b.option([]const u8, "iso", "path to the Xbox 360 ISO"),
        .out = b.option([]const u8, "out", "output path"),
        .key = b.option([]const u8, "key", "path to a 16-byte XEX key"),
        .tree = b.option([]const u8, "tree", "extracted game tree"),
        .xex = b.option([]const u8, "xex", "path to a XEX file"),
        .xextool = b.option([]const u8, "xextool", "XexTool binary for the unlock step (defaults to PATH)"),
    };
}

fn addExtractStep(b: *std.Build, exe: *std.Build.Step.Compile, opts: Options) void {
    const step = b.step("extract", "Extract the disc tree from an ISO");
    const iso = opts.iso orelse return failStep(b, step, "-Diso=<path>");
    const out = opts.out orelse return failStep(b, step, "-Dout=<dir>");

    const run = b.addRunArtifact(exe);
    run.addArgs(&.{ "extract", "--iso", iso, "--out", out });
    if (opts.key) |key| run.addArgs(&.{ "--key", key });
    step.dependOn(&run.step);
}

fn addAnalyzeStep(b: *std.Build, exe: *std.Build.Step.Compile, opts: Options) void {
    const step = b.step("analyze", "Report the XEX version, entry point and PE sections");
    if ((opts.tree == null) == (opts.xex == null)) {
        return failStep(b, step, "exactly one of -Dtree=<dir> or -Dxex=<path>");
    }

    const run = b.addRunArtifact(exe);
    run.addArgs(&.{"analyze"});
    if (opts.tree) |value| run.addArgs(&.{ "--tree", value });
    if (opts.xex) |value| run.addArgs(&.{ "--xex", value });
    if (opts.key) |key| run.addArgs(&.{ "--key", key });
    step.dependOn(&run.step);
}

/// Temporary: XexTool is external, GPLv3, and never part of the product or of `zig build`.
/// P1 replaces this step with `rezig xex`.
fn addUnlockStep(b: *std.Build, opts: Options) void {
    const step = b.step("unlock", "TEMPORARY: convert a retail XEX to an unencrypted copy with XexTool");
    const xex = opts.xex orelse return failStep(b, step, "-Dxex=<path>");
    const out = opts.out orelse b.fmt("{s}.unenc", .{xex});
    const tool = opts.xextool orelse "XexTool";

    const run = b.addSystemCommand(&.{ tool, "-e", "u", "-c", "u", "-o", out, xex });
    step.dependOn(&run.step);
}

fn failStep(b: *std.Build, step: *std.Build.Step, flag: []const u8) void {
    const fail = b.addFail(b.fmt("zig build {s} needs {s}", .{ step.name, flag }));
    step.dependOn(&fail.step);
}
