//! `rezig coverage`: report how much of the discovered code the decoder and emitter handle.

const std = @import("std");
const Io = std.Io;
const parse = @import("parse.zig");
const input = @import("input.zig");
const ppc_analyze = @import("../ppc/analyze.zig");
const decode = @import("../ppc/decode.zig");
const emit = @import("../codegen/emit.zig");

pub const Options = parse.Analyze;

pub const Missing = struct {
    name: []const u8,
    bo: u5 = 0,
    bi: u5 = 0,
    /// 1 = link, 2 = absolute, 4 = branch through CTR.
    flags: u8 = 0,
    count: u64,
    sample: u32,
    addr: u32,
};

pub const Summary = struct {
    functions: usize,
    instructions: u64,
    decoded: u64,
    emitted: u64,
    decode_failures: u64,
    fully_emittable: usize,
    missing: []Missing,
    undecoded: []Form,
};

/// Decoder gap grouped by primary opcode and its extension field, with one
/// sample word so the encoding can be assembled directly.
pub const Form = struct { primary: u6, xo: u16, count: u64, sample: u32, sample_addr: u32 };

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
        .undecoded = &.{},
    };

    var counts: std.AutoHashMapUnmanaged(u64, Missing) = .empty;
    defer counts.deinit(allocator);
    var forms: std.AutoHashMapUnmanaged(u32, Form) = .empty;
    defer forms.deinit(allocator);

    for (functions) |function| {
        var complete = true;
        const base = function.addr;
        const end = base +% @as(u32, @intCast(function.words.len)) * 4;
        for (function.words, 0..) |word, i| {
            summary.instructions += 1;
            const op = decode.decode(word) catch {
                summary.decode_failures += 1;
                const key = formKey(word);
                const entry = try forms.getOrPut(allocator, key);
                if (!entry.found_existing) {
                    entry.value_ptr.* = .{
                        .primary = @truncate(word >> 26),
                        .xo = @truncate(key & 0xffff),
                        .count = 0,
                        .sample = word,
                        .sample_addr = base + @as(u32, @intCast(i)) * 4,
                    };
                }
                entry.value_ptr.count += 1;
                complete = false;
                continue;
            };
            summary.decoded += 1;
            const at = base + @as(u32, @intCast(i)) * 4;
            if (emit.supportsAt(op, at, base, end)) {
                summary.emitted += 1;
            } else {
                complete = false;
                const entry = try counts.getOrPut(allocator, unsupportedKey(op));
                if (!entry.found_existing) {
                    const detail = branchDetail(op);
                    entry.value_ptr.* = .{
                        .name = @tagName(op),
                        .bo = detail.bo,
                        .bi = detail.bi,
                        .flags = detail.flags,
                        .count = 0,
                        .sample = word,
                        .addr = at,
                    };
                }
                entry.value_ptr.count += 1;
            }
        }
        if (complete) summary.fully_emittable += 1;
    }

    var list: std.ArrayList(Missing) = .empty;
    errdefer list.deinit(allocator);
    var it = counts.iterator();
    while (it.next()) |entry| {
        try list.append(allocator, entry.value_ptr.*);
    }
    const items = try list.toOwnedSlice(allocator);
    std.mem.sort(Missing, items, {}, missingGreaterThan);
    summary.missing = items;

    var form_list: std.ArrayList(Form) = .empty;
    errdefer form_list.deinit(allocator);
    var form_it = forms.iterator();
    while (form_it.next()) |entry| try form_list.append(allocator, entry.value_ptr.*);
    const form_items = try form_list.toOwnedSlice(allocator);
    std.mem.sort(Form, form_items, {}, formGreaterThan);
    summary.undecoded = form_items;
    return summary;
}

const BranchDetail = struct { bo: u5 = 0, bi: u5 = 0, flags: u8 = 0 };

fn branchDetail(op: decode.Instruction) BranchDetail {
    return switch (op) {
        .bc => |f| .{
            .bo = f.bo,
            .bi = f.bi,
            .flags = @intFromBool(f.link) | (@as(u8, @intFromBool(f.absolute)) << 1),
        },
        .bclr => |f| .{
            .bo = f.bo,
            .bi = f.bi,
            .flags = @intFromBool(f.link) |
                (@as(u8, @intFromBool(f.absolute)) << 1) |
                (@as(u8, @intFromBool(f.to_ctr)) << 2),
        },
        .bl => |f| .{ .flags = @as(u8, @intFromBool(f.absolute)) << 1 },
        else => .{},
    };
}

fn unsupportedKey(op: decode.Instruction) u64 {
    const detail = branchDetail(op);
    const tag: u16 = @backingInt(std.meta.activeTag(op));
    return (@as(u64, tag) << 32) |
        (@as(u64, detail.bo) << 24) |
        (@as(u64, detail.bi) << 16) |
        detail.flags;
}

/// Groups a rejected word by primary opcode and, where the ISA has one, its
/// extension field. Unknown primaries group under `xo = 0`.
fn formKey(word: u32) u32 {
    const primary: u6 = @truncate(word >> 26);
    const xo: u16 = switch (primary) {
        31, 19 => @truncate((word >> 1) & 0x3ff),
        4 => @truncate(word & 0x7ff),
        62, 58 => @truncate(word & 0x3),
        63 => @truncate((word >> 1) & 0x3ff),
        40, 44, 48, 50, 52, 59 => @truncate((word >> 1) & 0x1f),
        else => 0,
    };
    return (@as(u32, primary) << 16) | xo;
}

fn formGreaterThan(_: void, a: Form, b: Form) bool {
    return a.count > b.count;
}

fn missingGreaterThan(_: void, a: Missing, b: Missing) bool {
    if (a.count != b.count) return a.count > b.count;
    if (!std.mem.eql(u8, a.name, b.name)) return std.mem.lessThan(u8, a.name, b.name);
    if (a.bo != b.bo) return a.bo < b.bo;
    if (a.bi != b.bi) return a.bi < b.bi;
    return a.flags < b.flags;
}

pub fn run(allocator: std.mem.Allocator, io: Io, opts: Options, key: ?[16]u8) !void {
    var loaded = try input.load(allocator, io, opts.tree, opts.xex, opts.elf, key);
    defer loaded.deinit(allocator);
    const img = &loaded.image;

    const sections = try allocator.alloc(ppc_analyze.CodeSection, img.sections.len);
    defer allocator.free(sections);
    var count: usize = 0;
    for (img.sections) |s| {
        if (!img.isExecutable(s)) continue;
        sections[count] = .{ .addr = img.base_address + s.virtual_address, .bytes = img.sectionBytes(s) };
        count += 1;
    }

    const functions = try ppc_analyze.functionsFrom(allocator, sections[0..count], img.entry_point, loaded.seeds);
    defer ppc_analyze.freeFunctions(allocator, functions);

    var text_words: u64 = 0;
    for (sections[0..count]) |section| text_words += section.bytes.len / 4;

    var offsets = try allocator.alloc(usize, count);
    defer allocator.free(offsets);
    var running: usize = 0;
    for (sections[0..count], 0..) |section, i| {
        offsets[i] = running;
        running += section.bytes.len / 4;
    }
    const seen = try allocator.alloc(bool, running);
    defer allocator.free(seen);
    @memset(seen, false);
    var unique: u64 = 0;
    for (functions) |function| {
        for (0..function.words.len) |i| {
            const addr = function.addr + @as(u32, @intCast(i)) * 4;
            for (sections[0..count], 0..) |section, si| {
                if (addr < section.addr or addr >= section.addr + section.bytes.len) continue;
                const index = offsets[si] + (addr - section.addr) / 4;
                if (!seen[index]) {
                    seen[index] = true;
                    unique += 1;
                }
                break;
            }
        }
    }

    const summary = try collect(allocator, functions);
    defer allocator.free(summary.missing);
    defer allocator.free(summary.undecoded);

    var buf: [4096]u8 = undefined;
    var writer = Io.File.stdout().writer(io, &buf);
    const out = &writer.interface;

    try out.print("function seeds: {d}\n", .{loaded.seeds.len});
    try out.print("text words: {d}\n", .{text_words});
    try out.print("functions: {d}\n", .{summary.functions});
    try out.print("instructions: {d} ({d}.{d:0>2}% of .text)\n", .{
        summary.instructions,
        percent(summary.instructions, text_words),
        percent100(summary.instructions, text_words),
    });
    try out.print("unique instructions: {d} ({d}.{d:0>2}% of .text)\n", .{
        unique,
        percent(unique, text_words),
        percent100(unique, text_words),
    });
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
        try out.writeAll("unsupported forms (name, bo, bi, flags, count, sample, addr; flags: 1=link 2=absolute 4=ctr):\n");
        for (summary.missing) |entry| {
            try out.print("  {s} {d} {d} 0x{X} {d} 0x{X:0>8} 0x{X:0>8}\n", .{
                entry.name,
                entry.bo,
                entry.bi,
                entry.flags,
                entry.count,
                entry.sample,
                entry.addr,
            });
        }
    }

    if (summary.undecoded.len != 0) {
        try out.writeAll("undecoded forms (primary, xo, count, sample, addr):\n");
        for (summary.undecoded) |form| {
            try out.print("  {d:0>2} 0x{X:0>3} {d} 0x{X:0>8} 0x{X:0>8}\n", .{
                form.primary,
                form.xo,
                form.count,
                form.sample,
                form.sample_addr,
            });
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
    var mixed = [_]u32{ 0x60000000, 0x42000003, 0x00000000, 0x4e800020 };
    var clean = [_]u32{ 0x60000000, 0x4e800020 };
    var no_calls = [_]u32{};
    const functions = [_]ppc_analyze.Function{
        .{ .addr = 0x1000, .words = &mixed, .calls = &no_calls },
        .{ .addr = 0x2000, .words = &clean, .calls = &no_calls },
    };

    const summary = try collect(testing.allocator, &functions);
    defer testing.allocator.free(summary.missing);
    defer testing.allocator.free(summary.undecoded);

    try testing.expectEqual(@as(usize, 2), summary.functions);
    try testing.expectEqual(@as(u64, 6), summary.instructions);
    try testing.expectEqual(@as(u64, 5), summary.decoded);
    try testing.expectEqual(@as(u64, 4), summary.emitted);
    try testing.expectEqual(@as(u64, 1), summary.decode_failures);
    try testing.expectEqual(@as(usize, 1), summary.undecoded.len);
    try testing.expectEqual(@as(u64, 1), summary.undecoded[0].count);
    try testing.expectEqual(@as(usize, 1), summary.fully_emittable);
    try testing.expectEqual(@as(usize, 1), summary.missing.len);
    try testing.expectEqualStrings("bc", summary.missing[0].name);
    try testing.expectEqual(@as(u64, 1), summary.missing[0].count);
}

test "collect keeps branch form details and sample addresses" {
    // Two unsupported bc forms with different BO; one undecoded word.
    var forms = [_]u32{ 0x42000003, 0x42200003, 0x00000000, 0x4e800020 };
    var no_calls = [_]u32{};
    const functions = [_]ppc_analyze.Function{
        .{ .addr = 0x1000, .words = &forms, .calls = &no_calls },
    };

    const summary = try collect(testing.allocator, &functions);
    defer testing.allocator.free(summary.missing);
    defer testing.allocator.free(summary.undecoded);

    try testing.expectEqual(@as(usize, 2), summary.missing.len);
    var seen_16 = false;
    var seen_17 = false;
    for (summary.missing) |entry| {
        try testing.expectEqualStrings("bc", entry.name);
        try testing.expectEqual(@as(u64, 1), entry.count);
        if (entry.bo == 16) {
            seen_16 = true;
            try testing.expectEqual(@as(u32, 0x42000003), entry.sample);
            try testing.expectEqual(@as(u32, 0x1000), entry.addr);
        } else if (entry.bo == 17) {
            seen_17 = true;
            try testing.expectEqual(@as(u32, 0x42200003), entry.sample);
            try testing.expectEqual(@as(u32, 0x1004), entry.addr);
        }
    }
    try testing.expect(seen_16);
    try testing.expect(seen_17);

    try testing.expectEqual(@as(usize, 1), summary.undecoded.len);
    try testing.expectEqual(@as(u32, 0x1008), summary.undecoded[0].sample_addr);
}
