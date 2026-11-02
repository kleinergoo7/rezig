const std = @import("std");

/// Hard rule: `.zig-cache` never exceeds this. Every build trims the oldest
/// entries first, so the cap holds no matter what ran before.
const max_cache_bytes: u64 = 5 * 1024 * 1024 * 1024;

pub fn build(b: *std.Build) void {
    enforceCacheCap(b);
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const xextool = b.dependency("xextool", .{
        .target = target,
        .optimize = optimize,
    }).module("xextool");

    const exe = b.addExecutable(.{
        .name = "rezig",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{.{ .name = "xextool", .module = xextool }},
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    const run_step = b.step("run", "Run the rezig CLI");
    run_step.dependOn(&run_cmd.step);

    const test_ppc = b.createModule(.{
        .root_source_file = b.path("src/ppc/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const test_runtime = b.createModule(.{
        .root_source_file = b.path("src/runtime/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{.{ .name = "xextool", .module = xextool }},
        }),
    });
    const interp_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/interp/interp.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "rezig_ppc", .module = test_ppc },
                .{ .name = "rezig_runtime", .module = test_runtime },
            },
        }),
    });
    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);
    test_step.dependOn(&b.addRunArtifact(interp_tests).step);

    const opts = readOptions(b);
    addExtractStep(b, exe, opts);
    addAnalyzeStep(b, exe, opts);
    addCoverageStep(b, exe, opts);
    addXexStep(b, exe, opts);
    addGateStep(b, exe, opts, target, optimize);
    addBootStep(b, exe, opts, target, optimize);
    addPortabilityStep(b, xextool);
}

const Options = struct {
    iso: ?[]const u8,
    out: ?[]const u8,
    key: ?[]const u8,
    tree: ?[]const u8,
    xex: ?[]const u8,
    elf: ?[]const u8,
    slice: ?[]const u8,
    slice_list: ?[]const u8,
    budget: ?[]const u8,
};

/// Build options are global, so every step reads from this one table.
fn readOptions(b: *std.Build) Options {
    return .{
        .iso = b.option([]const u8, "iso", "path to the Xbox 360 ISO"),
        .out = b.option([]const u8, "out", "output path"),
        .key = b.option([]const u8, "key", "path to a 16-byte XEX key"),
        .tree = b.option([]const u8, "tree", "extracted game tree"),
        .xex = b.option([]const u8, "xex", "path to a XEX file"),
        .elf = b.option([]const u8, "elf", "path to an ELF32 PowerPC file"),
        .slice = b.option([]const u8, "slice", "number of functions to select"),
        .slice_list = b.option([]const u8, "slice-list", "frozen address list"),
        .budget = b.option([]const u8, "budget", "guest instructions for the boot run"),
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
    const sources = @as(u8, @intFromBool(opts.tree != null)) + @intFromBool(opts.xex != null) + @intFromBool(opts.elf != null);
    if (sources != 1) {
        return failStep(b, step, "exactly one of -Dtree=<dir>, -Dxex=<path> or -Delf=<path>");
    }

    const run = b.addRunArtifact(exe);
    run.addArgs(&.{"analyze"});
    if (opts.tree) |value| run.addArgs(&.{ "--tree", value });
    if (opts.xex) |value| run.addArgs(&.{ "--xex", value });
    if (opts.elf) |value| run.addArgs(&.{ "--elf", value });
    if (opts.key) |key| run.addArgs(&.{ "--key", key });
    step.dependOn(&run.step);
}

fn addCoverageStep(b: *std.Build, exe: *std.Build.Step.Compile, opts: Options) void {
    const step = b.step("coverage", "Report decoder and emitter coverage over discovered code");
    const sources = @as(u8, @intFromBool(opts.tree != null)) + @intFromBool(opts.xex != null) + @intFromBool(opts.elf != null);
    if (sources != 1) {
        return failStep(b, step, "exactly one of -Dtree=<dir>, -Dxex=<path> or -Delf=<path>");
    }

    const run = b.addRunArtifact(exe);
    run.addArgs(&.{"coverage"});
    if (opts.tree) |value| run.addArgs(&.{ "--tree", value });
    if (opts.xex) |value| run.addArgs(&.{ "--xex", value });
    if (opts.elf) |value| run.addArgs(&.{ "--elf", value });
    if (opts.key) |key| run.addArgs(&.{ "--key", key });
    step.dependOn(&run.step);
}

fn addXexStep(b: *std.Build, exe: *std.Build.Step.Compile, opts: Options) void {
    const step = b.step("xex", "Convert a retail XEX to an unencrypted copy");
    const xex = opts.xex orelse return failStep(b, step, "-Dxex=<path>");
    const out = opts.out orelse return failStep(b, step, "-Dout=<path>");

    const run = b.addRunArtifact(exe);
    run.addArgs(&.{ "xex", "--in", xex, "--out", out });
    if (opts.key) |key| run.addArgs(&.{ "--key", key });
    step.dependOn(&run.step);
}

/// Compile gate: regenerate the slice and type-check every emitted function against the real Ctx.
fn addGateStep(b: *std.Build, exe: *std.Build.Step.Compile, opts: Options, target: std.Build.ResolvedTarget, optimize: std.builtin.Optimize) void {
    const step = b.step("gate", "Compile the emitted slice against the runtime");
    const sources = @as(u8, @intFromBool(opts.tree != null)) + @intFromBool(opts.xex != null) + @intFromBool(opts.elf != null);
    if (sources != 1) {
        return failStep(b, step, "exactly one of -Dtree=<dir>, -Dxex=<path> or -Delf=<path>");
    }

    const codegen_run = b.addRunArtifact(exe);
    codegen_run.addArgs(&.{"codegen"});
    if (opts.tree) |value| codegen_run.addArgs(&.{ "--tree", value });
    if (opts.xex) |value| codegen_run.addArgs(&.{ "--xex", value });
    if (opts.elf) |value| codegen_run.addArgs(&.{ "--elf", value });
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

fn addBootStep(b: *std.Build, exe: *std.Build.Step.Compile, opts: Options, target: std.Build.ResolvedTarget, optimize: std.builtin.Optimize) void {
    const step = b.step("boot", "Build the whole-image recompiled binary and run its entry point");
    const xex = opts.xex orelse return failStep(b, step, "-Dxex=<path>");

    const codegen_run = b.addRunArtifact(exe);
    codegen_run.addArgs(&.{ "codegen", "--all", "--xex", xex });
    if (opts.key) |key| codegen_run.addArgs(&.{ "--key", key });
    codegen_run.addArgs(&.{"--out"});
    const out_dir = codegen_run.addOutputDirectoryArg("boot");
    const dispatch_path = out_dir.path(b, "dispatch.zig");

    const runtime_module = b.createModule(.{
        .root_source_file = b.path("src/runtime/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const image_module = b.createModule(.{
        .root_source_file = b.path("src/boot_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const slice_module = b.createModule(.{
        .root_source_file = dispatch_path,
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "rezig_runtime", .module = runtime_module }},
    });
    const boot_module = b.createModule(.{
        .root_source_file = b.path("src/boot/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "slice", .module = slice_module },
            .{ .name = "rezig_runtime", .module = runtime_module },
            .{ .name = "rezig_image", .module = image_module },
        },
    });
    const boot_exe = b.addExecutable(.{ .name = "rezig-boot", .root_module = boot_module });
    const run = b.addRunArtifact(boot_exe);
    run.addArg(xex);
    if (opts.key) |key| {
        run.addArg(key);
    } else if (opts.budget != null) {
        // Positional placeholder: the budget arg follows the key slot.
        run.addArg("-");
    }
    if (opts.budget) |budget| run.addArg(budget);
    step.dependOn(&run.step);
}

/// Tier A/B compile gate. Vulkan behaviour is a manual gate, not a CI gate.
fn addPortabilityStep(b: *std.Build, xextool: *std.Build.Module) void {
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
            .link_libc = true,
            .imports = &.{.{ .name = "xextool", .module = xextool }},
        });
        const obj = b.addObject(.{ .name = b.fmt("rezig-portability-{d}", .{i}), .root_module = mod });
        step.dependOn(&obj.step);
    }
}

fn failStep(b: *std.Build, step: *std.Build.Step, flag: []const u8) void {
    const fail = b.addFail(b.fmt("zig build {s} needs {s}", .{ step.name, flag }));
    step.dependOn(&fail.step);
}

/// Deletes the oldest `.zig-cache/o` and `.zig-cache/z` entries until the
/// whole cache fits `max_cache_bytes`. Never fails the build: on any error
/// the guard gives up and the build proceeds.
fn enforceCacheCap(b: *std.Build) void {
    enforceCacheCapInner(b.allocator, b.graph.io) catch {};
}

const CacheEntry = struct {
    parent: []const u8,
    name: []const u8,
    size: u64,
    mtime: i96,
};

fn enforceCacheCapInner(allocator: std.mem.Allocator, io: std.Io) !void {
    const Io = std.Io;
    const cwd = Io.Dir.cwd();
    var cache = cwd.openDir(io, ".zig-cache", .{ .iterate = true }) catch return;
    defer cache.close(io);

    // Transient leftovers from killed builds. Only entries untouched for over
    // an hour are swept, so the running build's own tmp dirs are never raced.
    // This sweep is safe because this repo never overlaps builds.
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    const stale_ns: i96 = std.time.ns_per_hour;
    var swept: u64 = 0;
    {
        var it = cache.iterate();
        while (it.next(io) catch null) |entry| {
            if (entry.kind != .directory) continue;
            if (!std.mem.startsWith(u8, entry.name, "tmp")) continue;
            const st = cache.statFile(io, entry.name, .{}) catch continue;
            if (now - st.mtime.nanoseconds < stale_ns) continue;
            const name = allocator.dupe(u8, entry.name) catch continue;
            defer allocator.free(name);
            swept +|= treeBytes(io, cache, name);
            cache.deleteTree(io, name) catch {};
        }
    }

    var total: u64 = 0;
    var candidates: std.ArrayList(CacheEntry) = .empty;
    defer {
        for (candidates.items) |entry| {
            allocator.free(entry.parent);
            allocator.free(entry.name);
        }
        candidates.deinit(allocator);
    }
    {
        var it = cache.iterate();
        while (it.next(io) catch null) |entry| {
            if (entry.kind != .directory) continue;
            if (std.mem.startsWith(u8, entry.name, "tmp")) continue;
            const evictable = std.mem.eql(u8, entry.name, "o") or std.mem.eql(u8, entry.name, "z");
            var sub = cache.openDir(io, entry.name, .{ .iterate = true }) catch continue;
            defer sub.close(io);
            if (!evictable) {
                total +|= treeBytesOpen(io, sub);
                continue;
            }
            var sub_it = sub.iterate();
            while (sub_it.next(io) catch null) |hash| {
                if (hash.kind != .directory) continue;
                const st = sub.statFile(io, hash.name, .{}) catch continue;
                var hdir = sub.openDir(io, hash.name, .{ .iterate = true }) catch continue;
                const size = treeBytesOpen(io, hdir);
                hdir.close(io);
                total +|= size;
                try candidates.append(allocator, .{
                    .parent = try allocator.dupe(u8, entry.name),
                    .name = try allocator.dupe(u8, hash.name),
                    .size = size,
                    .mtime = st.mtime.nanoseconds,
                });
            }
        }
    }

    if (total <= max_cache_bytes) {
        if (swept != 0) std.debug.print("cache: swept {d} MiB of tmp leftovers, total {d} MiB\n", .{ swept >> 20, total >> 20 });
        return;
    }
    std.mem.sort(CacheEntry, candidates.items, {}, struct {
        fn lessThan(_: void, a: CacheEntry, b: CacheEntry) bool {
            return a.mtime < b.mtime;
        }
    }.lessThan);
    var freed: u64 = swept;
    for (candidates.items) |entry| {
        if (total - freed <= max_cache_bytes) break;
        var parent = cache.openDir(io, entry.parent, .{}) catch continue;
        parent.deleteTree(io, entry.name) catch {};
        parent.close(io);
        freed +|= entry.size;
    }
    std.debug.print("cache: cap {d} MiB exceeded, evicted oldest entries, freed {d} MiB\n", .{ max_cache_bytes >> 20, freed >> 20 });
}

/// Byte size of the tree at `path` relative to `dir`.
fn treeBytes(io: std.Io, dir: std.Io.Dir, path: []const u8) u64 {
    var sub = dir.openDir(io, path, .{ .iterate = true }) catch return 0;
    const size = treeBytesOpen(io, sub);
    sub.close(io);
    return size;
}

fn treeBytesOpen(io: std.Io, dir: std.Io.Dir) u64 {
    var total: u64 = 0;
    var it = dir.iterate();
    while (it.next(io) catch return total) |entry| {
        if (entry.kind == .directory) {
            var sub = dir.openDir(io, entry.name, .{ .iterate = true }) catch continue;
            total +|= treeBytesOpen(io, sub);
            sub.close(io);
        } else {
            const st = dir.statFile(io, entry.name, .{}) catch continue;
            total +|= st.size;
        }
    }
    return total;
}
