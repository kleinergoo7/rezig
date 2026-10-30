//! Function discovery over executable sections.

const std = @import("std");
const decode = @import("decode.zig");

pub const max_function_insns: u32 = 1024;
pub const max_functions: u32 = 100_000;

pub const Error = error{
    OutOfRange,
    Unsupported,
    NoTerminator,
    TooManyFunctions,
} || std.mem.Allocator.Error;

pub const CodeSection = struct { addr: u32, bytes: []const u8 };

pub const Function = struct {
    addr: u32,
    words: []u32,
    calls: []u32,
};

pub fn functions(
    allocator: std.mem.Allocator,
    sections: []const CodeSection,
    entry: u32,
) Error![]Function {
    var found: std.ArrayList(Function) = .empty;
    errdefer {
        for (found.items) |f| {
            allocator.free(f.words);
            allocator.free(f.calls);
        }
        found.deinit(allocator);
    }

    var seen: std.AutoHashMapUnmanaged(u32, void) = .empty;
    defer seen.deinit(allocator);

    var queue: std.ArrayList(u32) = .empty;
    defer queue.deinit(allocator);

    try enqueue(allocator, &queue, &seen, entry);

    while (queue.pop()) |addr| {
        var err_addr: u32 = 0;
        const words = functionAt(allocator, sections, addr, &err_addr) catch |e| switch (e) {
            error.OutOfRange => continue,
            else => |other| return other,
        };
        errdefer allocator.free(words);

        var calls: std.ArrayList(u32) = .empty;
        errdefer calls.deinit(allocator);

        var i: usize = 0;
        while (i < words.len) : (i += 1) {
            const insn = decode.decode(words[i]) catch continue;
            if (decode.isBranchToLink(insn)) |rel| {
                const target = addr +% @as(u32, @intCast(i)) *% 4 +% rel;
                try calls.append(allocator, target);
                try enqueue(allocator, &queue, &seen, target);
            }
        }

        if (found.items.len >= max_functions) return error.TooManyFunctions;
        try found.append(allocator, .{
            .addr = addr,
            .words = words,
            .calls = try calls.toOwnedSlice(allocator),
        });
    }

    const result = try found.toOwnedSlice(allocator);
    std.mem.sort(Function, result, {}, functionLessThan);
    return result;
}

pub fn freeFunctions(allocator: std.mem.Allocator, list: []Function) void {
    for (list) |f| {
        allocator.free(f.words);
        allocator.free(f.calls);
    }
    allocator.free(list);
}

/// Decodes from `addr` up to and including the first `blr`.
/// On error, `err_addr` names the guest address that caused it.
pub fn functionAt(
    allocator: std.mem.Allocator,
    sections: []const CodeSection,
    addr: u32,
    err_addr: *u32,
) Error![]u32 {
    err_addr.* = addr;

    const section = findSection(sections, addr) orelse return error.OutOfRange;
    const start = (addr - section.addr) / 4;

    var words: std.ArrayList(u32) = .empty;
    errdefer words.deinit(allocator);

    var index = start;
    while (index < section.bytes.len / 4) : (index += 1) {
        if (words.items.len >= max_function_insns) {
            err_addr.* = section.addr + @as(u32, @intCast(index)) * 4;
            return error.NoTerminator;
        }

        const at = index * 4;
        const word = std.mem.readInt(u32, section.bytes[at..][0..4], .big);
        err_addr.* = section.addr + @as(u32, @intCast(at));

        const insn = decode.decode(word) catch return error.Unsupported;
        try words.append(allocator, word);

        if (decode.isReturn(insn)) return words.toOwnedSlice(allocator);
    }

    err_addr.* = section.addr + @as(u32, @intCast(section.bytes.len));
    return error.NoTerminator;
}

fn enqueue(
    allocator: std.mem.Allocator,
    queue: *std.ArrayList(u32),
    seen: *std.AutoHashMapUnmanaged(u32, void),
    addr: u32,
) Error!void {
    const gop = try seen.getOrPut(allocator, addr);
    if (gop.found_existing) return;
    try queue.append(allocator, addr);
}

fn findSection(sections: []const CodeSection, addr: u32) ?CodeSection {
    for (sections) |s| {
        if (addr >= s.addr and addr - s.addr <= s.bytes.len -| 4 and s.bytes.len >= 4) return s;
    }
    return null;
}

fn functionLessThan(_: void, a: Function, b: Function) bool {
    return a.addr < b.addr;
}

const testing = std.testing;

fn beBytes(allocator: std.mem.Allocator, words: []const u32) ![]u8 {
    const bytes = try allocator.alloc(u8, words.len * 4);
    for (words, 0..) |w, i| std.mem.writeInt(u32, bytes[i * 4 ..][0..4], w, .big);
    return bytes;
}

const save = 0x9421ffa0; // stwu r1,-96(r1)
const ret = 0x4e800020; // blr

test "discovers reached functions and their calls" {
    const code = [_]u32{
        save, 0x4800001d, ret, // 0x100: call 0x120, return
        save, 0x38600001, ret, // 0x120: addi r3,r0,1, return
        save, 0x38600002, ret, // 0x130: not reached by 0x120
    };
    const bytes = try beBytes(testing.allocator, &code);
    defer testing.allocator.free(bytes);
    const sections = [_]CodeSection{.{ .addr = 0x100, .bytes = bytes }};

    const list = try functions(testing.allocator, &sections, 0x100);
    defer freeFunctions(testing.allocator, list);

    try testing.expectEqual(@as(usize, 2), list.len);
    try testing.expectEqual(@as(u32, 0x100), list[0].addr);
    try testing.expectEqual(@as(u32, 0x120), list[1].addr);
    try testing.expectEqual(@as(usize, 1), list[0].calls.len);
    try testing.expectEqual(@as(u32, 0x120), list[0].calls[0]);
}

test "address outside every section is out of range" {
    const code = [_]u32{ret};
    const bytes = try beBytes(testing.allocator, &code);
    defer testing.allocator.free(bytes);
    const sections = [_]CodeSection{.{ .addr = 0x100, .bytes = bytes }};
    var err_addr: u32 = 0;
    try testing.expectError(error.OutOfRange, functionAt(testing.allocator, &sections, 0x500, &err_addr));
    try testing.expectEqual(@as(u32, 0x500), err_addr);
}

test "a function without blr reports its address" {
    var code: [max_function_insns + 1]u32 = @splat(save);
    const bytes = try beBytes(testing.allocator, &code);
    defer testing.allocator.free(bytes);
    const sections = [_]CodeSection{.{ .addr = 0x100, .bytes = bytes }};
    var err_addr: u32 = 0;
    try testing.expectError(error.NoTerminator, functionAt(testing.allocator, &sections, 0x100, &err_addr));
    try testing.expectEqual(@as(u32, 0x100 + max_function_insns * 4), err_addr);
    _ = &code;
}

test "an undecodable word reports its address" {
    const code = [_]u32{ save, 0x00000000, ret };
    const bytes = try beBytes(testing.allocator, &code);
    defer testing.allocator.free(bytes);
    const sections = [_]CodeSection{.{ .addr = 0x100, .bytes = bytes }};
    var err_addr: u32 = 0;
    try testing.expectError(error.Unsupported, functionAt(testing.allocator, &sections, 0x104, &err_addr));
    try testing.expectEqual(@as(u32, 0x104), err_addr);
}
