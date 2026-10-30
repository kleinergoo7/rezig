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
    addGateStep(b, exe, opts, target, optimize);
    addPortabilityStep(b);
}

const Options = struct {
    iso: ?[]const u8,
    out: ?[]const u8,
    key: ?[]const u8,
    tree: ?[]const u8,
    xex: ?[]const u8,
    xextool: ?[]const u8,
    slice: ?[]const u8,
    slice_list: ?[]const u8,
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
        .slice = b.option([]const u8, "slice", "number of functions to select"),
        .slice_list = b.option([]const u8, "slice-list", "frozen address list"),
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

/// Compile gate: regenerate the slice and type-check every emitted function against the real Ctx.
fn addGateStep(b: *std.Build, exe: *std.Build.Step.Compile, opts: Options, target: std.Build.ResolvedTarget, optimize: std.builtin.Optimize) void {
    const step = b.step("gate", "Compile the emitted slice against the runtime");
    if ((opts.tree == null) == (opts.xex == null)) {
        return failStep(b, step, "exactly one of -Dtree=<dir> or -Dxex=<path>");
    }

    const codegen_run = b.addRunArtifact(exe);
    codegen_run.addArgs(&.{"codegen"});
    if (opts.tree) |value| codegen_run.addArgs(&.{ "--tree", value });
    if (opts.xex) |value| codegen_run.addArgs(&.{ "--xex", value });
    if (opts.key) |key| codegen_run.addArgs(&.{ "--key", key });
    if (opts.slice) |n| codegen_run.addArgs(&.{ "--slice", n });
    if (opts.slice_list) |path| codegen_run.addArgs(&.{ "--slice-list", path });

    // `--out` must directly precede the build-managed output directory argument.
    codegen_run.addArgs(&.{"--out"});
    const out_dir = codegen_run.addOutputDirectoryArg("gate");
    const slice_path = out_dir.path(b, "slice.zig");
    const runtime_module = b.createModule(.{
        .root_source_file = b.path("src/runtime/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const slice_module = b.createModule(.{
        .root_source_file = slice_path,
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "rezig_runtime", .module = runtime_module }},
    });
    const compiled = b.addObject(.{ .name = "slice", .root_module = slice_module });
    compiled.step.dependOn(&codegen_run.step);
    step.dependOn(&compiled.step);

    const ppc_module = b.createModule(.{
        .root_source_file = b.path("src/ppc/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const interp_module = b.createModule(.{
        .root_source_file = b.path("src/interp/interp.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "rezig_ppc", .module = ppc_module },
            .{ .name = "rezig_runtime", .module = runtime_module },
        },
    });

    const gate_module = b.createModule(.{
        .root_source_file = b.path("tests/gate.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "slice", .module = slice_module },
            .{ .name = "rezig_runtime", .module = runtime_module },
            .{ .name = "rezig_interp", .module = interp_module },
        },
    });
    const gate_test = b.addTest(.{ .root_module = gate_module });
    const run_gate = b.addRunArtifact(gate_test);
    run_gate.step.dependOn(&codegen_run.step);
    step.dependOn(&run_gate.step);
}

/// Tier A/B compile gate. Vulkan behaviour is a manual gate, not a CI gate.
fn addPortabilityStep(b: *std.Build) void {
    const step = b.step("portability", "Cross-compile the CLI for x86_64-windows and aarch64-linux");
    const queries = [_]std.Target.Query{
        .{ .cpu_arch = .x86_64, .os_tag = .windows },
        .{ .cpu_arch = .aarch64, .os_tag = .linux },
    };
    for (queries, 0..) |query, i| {
        const mod = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = b.resolveTargetQuery(query),
            .optimize = .ReleaseSafe,
        });
        const obj = b.addObject(.{ .name = b.fmt("rezig-portability-{d}", .{i}), .root_module = mod });
        step.dependOn(&obj.step);
    }
}

fn failStep(b: *std.Build, step: *std.Build.Step, flag: []const u8) void {
    const fail = b.addFail(b.fmt("zig build {s} needs {s}", .{ step.name, flag }));
    step.dependOn(&fail.step);
}
