//! `rezig coverage`: report how much of the discovered code the decoder and emitter handle.

const std = @import("std");
const Io = std.Io;
const parse = @import("parse.zig");
const image = @import("../xex/image.zig");
const ppc_analyze = @import("../ppc/analyze.zig");
const decode = @import("../ppc/decode.zig");
const emit = @import("../codegen/emit.zig");

pub const Options = parse.Analyze;

pub const Missing = struct { name: []const u8, count: u64 };

pub const Summary = struct {
    functions: usize,
    instructions: u64,
    decoded: u64,
    emitted: u64,
    decode_failures: u64,
    fully_emittable: usize,
    missing: []Missing,
    /// Counts per 6-bit primary opcode for words the decoder rejects.
    undecoded: [64]u64,
};

const Undecoded = struct { primary: u6, count: u64 };

/// Counts decoder and emitter coverage over already-discovered functions.
/// The caller owns `summary.missing`.
pub fn collect(allocator: std.mem.Allocator, functions: []const ppc_analyze.Function) !Summary {
    var summary = Summary{
        .functions = functions.len,
        .instructions = 0,
        .decoded = 0,
        .emitted = 0,
        .decode_failures = 0,
        .fully_emittable = 0,
        .missing = &.{},
        .undecoded = @splat(0),
    };

    var counts: std.StringHashMapUnmanaged(u64) = .empty;
    defer counts.deinit(allocator);

    for (functions) |function| {
        var complete = true;
        const base = function.addr;
        const end = base +% @as(u32, @intCast(function.words.len)) * 4;
        for (function.words, 0..) |word, i| {
            summary.instructions += 1;
            const op = decode.decode(word) catch {
                summary.decode_failures += 1;
                summary.undecoded[word >> 26] += 1;
                complete = false;
                continue;
            };
            summary.decoded += 1;
            const at = base + @as(u32, @intCast(i)) * 4;
            if (emit.supportsAt(op, at, base, end)) {
                summary.emitted += 1;
            } else {
                complete = false;
                const entry = try counts.getOrPut(allocator, @tagName(op));
                if (!entry.found_existing) entry.value_ptr.* = 0;
                entry.value_ptr.* += 1;
            }
        }
        if (complete) summary.fully_emittable += 1;
    }

    var list: std.ArrayList(Missing) = .empty;
    errdefer list.deinit(allocator);
    var it = counts.iterator();
    while (it.next()) |entry| {
        try list.append(allocator, .{ .name = entry.key_ptr.*, .count = entry.value_ptr.* });
    }
    const items = try list.toOwnedSlice(allocator);
    std.mem.sort(Missing, items, {}, missingGreaterThan);
    summary.missing = items;
    return summary;
}

fn missingGreaterThan(_: void, a: Missing, b: Missing) bool {
    return a.count > b.count;
}

fn undecodedGreaterThan(_: void, a: Undecoded, b: Undecoded) bool {
    return a.count > b.count;
}

pub fn run(allocator: std.mem.Allocator, io: Io, opts: Options, key: ?[16]u8) !void {
    const xex_path = if (opts.xex) |p|
        try allocator.dupe(u8, p)
    else
        try std.fmt.allocPrint(allocator, "{s}/default.xex", .{opts.tree.?});
    defer allocator.free(xex_path);

    var img = try image.load(allocator, io, xex_path, key);
    defer img.deinit(allocator);

    const sections = try allocator.alloc(ppc_analyze.CodeSection, img.sections.len);
    defer allocator.free(sections);
    var count: usize = 0;
    for (img.sections) |s| {
        if (!img.isExecutable(s)) continue;
        sections[count] = .{ .addr = img.base_address + s.virtual_address, .bytes = img.sectionBytes(s) };
        count += 1;
    }

    const functions = try ppc_analyze.functions(allocator, sections[0..count], img.entry_point);
    defer ppc_analyze.freeFunctions(allocator, functions);

    const summary = try collect(allocator, functions);
    defer allocator.free(summary.missing);

    var buf: [4096]u8 = undefined;
    var writer = Io.File.stdout().writer(io, &buf);
    const out = &writer.interface;

    try out.print("functions: {d}\n", .{summary.functions});
    try out.print("instructions: {d}\n", .{summary.instructions});
    try out.print("decoded: {d} ({d}.{d:0>2}%)\n", .{
        summary.decoded,
        percent(summary.decoded, summary.instructions),
        percent100(summary.decoded, summary.instructions),
    });
    try out.print("emitted: {d} ({d}.{d:0>2}%)\n", .{
        summary.emitted,
        percent(summary.emitted, summary.instructions),
        percent100(summary.emitted, summary.instructions),
    });
    try out.print("decode failures: {d}\n", .{summary.decode_failures});
    try out.print("fully emittable functions: {d} ({d}.{d:0>2}%)\n", .{
        summary.fully_emittable,
        percent(summary.fully_emittable, summary.functions),
        percent100(summary.fully_emittable, summary.functions),
    });

    if (summary.missing.len != 0) {
        try out.writeAll("unsupported opcodes:\n");
        for (summary.missing[0..@min(summary.missing.len, 20)]) |entry| {
            try out.print("  {s} {d}\n", .{ entry.name, entry.count });
        }
    }

    var undecoded: [64]Undecoded = undefined;
    var undecoded_len: usize = 0;
    for (summary.undecoded, 0..) |hits, primary| {
        if (hits == 0) continue;
        undecoded[undecoded_len] = .{ .primary = @intCast(primary), .count = hits };
        undecoded_len += 1;
    }
    std.mem.sort(Undecoded, undecoded[0..undecoded_len], {}, undecodedGreaterThan);
    if (undecoded_len != 0) {
        try out.writeAll("undecoded primary opcodes:\n");
        for (undecoded[0..@min(undecoded_len, 20)]) |entry| {
            try out.print("  {d:0>2} {d}\n", .{ entry.primary, entry.count });
        }
    }
    try out.flush();
}

fn percent(part: u64, whole: u64) u64 {
    if (whole == 0) return 0;
    return part * 100 / whole;
}

fn percent100(part: u64, whole: u64) u64 {
    if (whole == 0) return 0;
    return part * 10_000 / whole % 100;
}

const testing = std.testing;

test "collect separates emitted instructions from decoder gaps" {
    var mixed = [_]u32{ 0x60000000, 0xfc22182a, 0x00000000, 0x4e800020 };
    var clean = [_]u32{ 0x60000000, 0x4e800020 };
    var no_calls = [_]u32{};
    const functions = [_]ppc_analyze.Function{
        .{ .addr = 0x1000, .words = &mixed, .calls = &no_calls },
        .{ .addr = 0x2000, .words = &clean, .calls = &no_calls },
    };

    const summary = try collect(testing.allocator, &functions);
    defer testing.allocator.free(summary.missing);

    try testing.expectEqual(@as(usize, 2), summary.functions);
    try testing.expectEqual(@as(u64, 6), summary.instructions);
    try testing.expectEqual(@as(u64, 5), summary.decoded);
    try testing.expectEqual(@as(u64, 4), summary.emitted);
    try testing.expectEqual(@as(u64, 1), summary.decode_failures);
    try testing.expectEqual(@as(u64, 1), summary.undecoded[0]);
    try testing.expectEqual(@as(usize, 1), summary.fully_emittable);
    try testing.expectEqual(@as(usize, 1), summary.missing.len);
    try testing.expectEqualStrings("fadd", summary.missing[0].name);
    try testing.expectEqual(@as(u64, 1), summary.missing[0].count);
}
