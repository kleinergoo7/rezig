//! Slice selection: leaf functions the emitter fully supports, plus the frozen address list.

const std = @import("std");
const Io = std.Io;
const analyze = @import("../ppc/analyze.zig");
const emit = @import("emit.zig");
const decode = @import("../ppc/decode.zig");

pub const max_insns: usize = 40;

pub const Error = error{NotEnoughFunctions} || analyze.Error;

pub const Candidate = struct { addr: u32, words: []const u32 };

/// Picks leaf functions in address order: no calls, 1..40 instructions, ends in blr, and every
/// instruction is one the emitter lowers.
pub fn select(
    allocator: std.mem.Allocator,
    sections: []const analyze.CodeSection,
    entry: u32,
    count: u32,
) Error![]Candidate {
    const found = try analyze.functions(allocator, sections, entry);
    defer analyze.freeFunctions(allocator, found);

    var picked: std.ArrayList(Candidate) = .empty;
    errdefer {
        for (picked.items) |c| allocator.free(c.words);
        picked.deinit(allocator);
    }

    for (found) |f| {
        if (picked.items.len >= count) break;
        if (f.calls.len != 0) continue;
        if (f.words.len == 0 or f.words.len > max_insns) continue;
        if (!supportedAll(f.words)) continue;
        const words = try allocator.dupe(u32, f.words);
        errdefer allocator.free(words);
        try picked.append(allocator, .{ .addr = f.addr, .words = words });
    }

    if (picked.items.len < count) return error.NotEnoughFunctions;
    return picked.toOwnedSlice(allocator);
}

pub fn freeCandidates(allocator: std.mem.Allocator, list: []Candidate) void {
    for (list) |c| allocator.free(c.words);
    allocator.free(list);
}

fn supportedAll(words: []const u32) bool {
    for (words) |word| {
        const op = decode.decode(word) catch return false;
        if (!emit.supports(op)) return false;
    }
    return true;
}

pub fn writeAddressList(
    allocator: std.mem.Allocator,
    io: Io,
    path: []const u8,
    addrs: []const u32,
) !void {
    const json = try std.json.Stringify.valueAlloc(allocator, .{ .abi = @as(u32, 1), .addresses = addrs }, .{ .whitespace = .indent_2 });
    defer allocator.free(json);

    var dir = try Io.Dir.cwd().createDirPathOpen(io, std.fs.path.dirname(path) orelse ".", .{});
    defer dir.close(io);
    var atomic = try dir.createFileAtomic(io, std.fs.path.basename(path), .{ .replace = true });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, json);
    try atomic.replace(io);
}

pub fn readAddressList(allocator: std.mem.Allocator, io: Io, path: []const u8) ![]u32 {
    const text = try Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1 << 20));
    defer allocator.free(text);

    const Wire = struct { abi: u32, addresses: []u32 };
    var parsed = try std.json.parseFromSlice(Wire, allocator, text, .{});
    defer parsed.deinit();
    if (parsed.value.abi != 1) return error.UnsupportedAbi;
    return allocator.dupe(u32, parsed.value.addresses);
}

const testing = std.testing;

test "selects only supported leaves in address order" {
    const ret = 0x4e800020;
    const addi = 0x38600001;
    const words = [_]u32{
        0x4800000d, 0x48000011, ret, // 0x100: calls 0x10c and 0x114
        addi, ret, // 0x10c leaf
        addi, addi, ret, // 0x114 leaf
    };
    const bytes = try beBytes(testing.allocator, &words);
    defer testing.allocator.free(bytes);
    const sections = [_]analyze.CodeSection{.{ .addr = 0x100, .bytes = bytes }};

    const picked = try select(testing.allocator, &sections, 0x100, 2);
    defer freeCandidates(testing.allocator, picked);

    try testing.expectEqual(@as(u32, 0x10c), picked[0].addr);
    try testing.expectEqual(@as(u32, 0x114), picked[1].addr);
}

test "asking for more than exists fails" {
    const ret = 0x4e800020;
    const words = [_]u32{ret};
    const bytes = try beBytes(testing.allocator, &words);
    defer testing.allocator.free(bytes);
    const sections = [_]analyze.CodeSection{.{ .addr = 0x100, .bytes = bytes }};

    try testing.expectError(error.NotEnoughFunctions, select(testing.allocator, &sections, 0x100, 2));
}

test "address list round trips" {
    const io = Io.Threaded.global_single_threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/addresses.json", .{tmp.sub_path});

    const addrs = [_]u32{ 0x100, 0x120 };
    try writeAddressList(testing.allocator, io, path, &addrs);

    const back = try readAddressList(testing.allocator, io, path);
    defer testing.allocator.free(back);
    try testing.expectEqualSlices(u32, &addrs, back);
}

fn beBytes(allocator: std.mem.Allocator, words: []const u32) ![]u8 {
    const bytes = try allocator.alloc(u8, words.len * 4);
    for (words, 0..) |w, i| std.mem.writeInt(u32, bytes[i * 4 ..][0..4], w, .big);
    return bytes;
}
