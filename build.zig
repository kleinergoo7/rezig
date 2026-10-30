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

    addExtractStep(b, exe);
    addAnalyzeStep(b, exe);
}

fn addExtractStep(b: *std.Build, exe: *std.Build.Step.Compile) void {
    const step = b.step("extract", "Extract the disc tree from an ISO");
    const iso = b.option([]const u8, "iso", "path to the Xbox 360 ISO") orelse
        return failStep(b, step, "-Diso=<path>");
    const out = b.option([]const u8, "out", "output game tree") orelse
        return failStep(b, step, "-Dout=<dir>");

    const run = b.addRunArtifact(exe);
    run.addArgs(&.{ "extract", "--iso", iso, "--out", out });
    if (b.option([]const u8, "key", "path to a 16-byte XEX key")) |key| {
        run.addArgs(&.{ "--key", key });
    }
    step.dependOn(&run.step);
}

fn addAnalyzeStep(b: *std.Build, exe: *std.Build.Step.Compile) void {
    const step = b.step("analyze", "Report the XEX version, entry point and PE sections");
    const tree = b.option([]const u8, "tree", "extracted game tree");
    const xex = b.option([]const u8, "xex", "path to a XEX file");
    if ((tree == null) == (xex == null)) {
        return failStep(b, step, "exactly one of -Dtree=<dir> or -Dxex=<path>");
    }

    const run = b.addRunArtifact(exe);
    run.addArgs(&.{"analyze"});
    if (tree) |value| run.addArgs(&.{ "--tree", value });
    if (xex) |value| run.addArgs(&.{ "--xex", value });
    if (b.option([]const u8, "key", "path to a 16-byte XEX key")) |key| {
        run.addArgs(&.{ "--key", key });
    }
    step.dependOn(&run.step);
}

fn failStep(b: *std.Build, step: *std.Build.Step, comptime flag: []const u8) void {
    const fail = b.addFail(b.fmt("zig build {s} needs -D{s}", .{ step.name, flag }));
    step.dependOn(&fail.step);
}
