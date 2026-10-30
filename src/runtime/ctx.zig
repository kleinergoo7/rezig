//! Guest context: registers, memory window and the fault slot.

const std = @import("std");
const memory = @import("memory.zig");

pub const FaultKind = enum { none, load, store, fetch, unsupported };

pub const Fault = struct {
    kind: FaultKind = .none,
    addr: u32 = 0,
    size: u8 = 0,
};

pub const Ctx = struct {
    gpr: [32]u64,
    fpr: [32]f64,
    vmx: [128][16]u8,
    cr: u32,
    xer: u32,
    lr: u32,
    ctr: u32,
    mem: memory.Memory,
    fault: Fault,

    pub fn init(mem: memory.Memory) Ctx {
        return .{
            .gpr = @splat(0),
            .fpr = @splat(0.0),
            .vmx = @splat(@splat(0)),
            .cr = 0,
            .xer = 0,
            .lr = 0,
            .ctr = 0,
            .mem = mem,
            .fault = .{},
        };
    }

    pub fn resetFault(self: *Ctx) void {
        self.fault = .{};
    }

    pub fn load8(self: *Ctx, addr: u32) u64 {
        return self.load(u8, addr, .load);
    }

    pub fn load16(self: *Ctx, addr: u32) u64 {
        return self.load(u16, addr, .load);
    }

    pub fn load32(self: *Ctx, addr: u32) u64 {
        return self.load(u32, addr, .load);
    }

    pub fn load64(self: *Ctx, addr: u32) u64 {
        return self.load(u64, addr, .load);
    }

    pub fn store8(self: *Ctx, addr: u32, value: u64) void {
        self.store(u8, addr, value, .store);
    }

    pub fn store16(self: *Ctx, addr: u32, value: u64) void {
        self.store(u16, addr, value, .store);
    }

    pub fn store32(self: *Ctx, addr: u32, value: u64) void {
        self.store(u32, addr, value, .store);
    }

    pub fn store64(self: *Ctx, addr: u32, value: u64) void {
        self.store(u64, addr, value, .store);
    }

    pub fn fetchInsn(self: *Ctx, addr: u32) u32 {
        return @intCast(self.load(u32, addr, .fetch));
    }

    fn load(self: *Ctx, comptime T: type, addr: u32, kind: FaultKind) u64 {
        const size = @sizeOf(T);
        if (!self.mem.contains(addr, size)) {
            self.recordFault(kind, addr, size);
            return 0;
        }
        const offset = addr - self.mem.base;
        return std.mem.readInt(T, self.mem.data[offset..][0..size], .big);
    }

    fn store(self: *Ctx, comptime T: type, addr: u32, value: u64, kind: FaultKind) void {
        const size = @sizeOf(T);
        if (!self.mem.contains(addr, size)) {
            self.recordFault(kind, addr, size);
            return;
        }
        const offset = addr - self.mem.base;
        // Truncation is the guest write width; the upper bits are discarded by the instruction.
        std.mem.writeInt(T, self.mem.data[offset..][0..size], @truncate(value), .big);
    }

    /// The first fault wins until `resetFault`, so the original cause is never masked.
    fn recordFault(self: *Ctx, kind: FaultKind, addr: u32, size: u8) void {
        if (self.fault.kind != .none) return;
        self.fault = .{ .kind = kind, .addr = addr, .size = size };
    }
};

const testing = std.testing;

fn testCtx(buf: []u8) Ctx {
    return Ctx.init(.{ .base = 0x1000, .data = buf });
}

test "store32 writes big endian and load32 reads it" {
    var buf: [64]u8 = @splat(0);
    var ctx = testCtx(&buf);

    ctx.store32(0x1000, 0x11223344);
    try testing.expectEqualSlices(u8, &.{ 0x11, 0x22, 0x33, 0x44 }, buf[0..4]);
    try testing.expectEqual(@as(u64, 0x11223344), ctx.load32(0x1000));
}

test "64-bit round trip is big endian" {
    var buf: [64]u8 = @splat(0);
    var ctx = testCtx(&buf);

    ctx.store64(0x1008, 0x0102030405060708);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, buf[8..16]);
    try testing.expectEqual(@as(u64, 0x0102030405060708), ctx.load64(0x1008));
}

test "out of range load records the first fault" {
    var buf: [16]u8 = @splat(0);
    var ctx = testCtx(&buf);

    try testing.expectEqual(@as(u64, 0), ctx.load32(0x1010));
    try testing.expectEqual(FaultKind.load, ctx.fault.kind);
    try testing.expectEqual(@as(u32, 0x1010), ctx.fault.addr);
    try testing.expectEqual(@as(u8, 4), ctx.fault.size);

    _ = ctx.load8(0x2000);
    try testing.expectEqual(@as(u32, 0x1010), ctx.fault.addr);

    ctx.resetFault();
    try testing.expectEqual(FaultKind.none, ctx.fault.kind);
}

test "out of range store changes nothing" {
    var buf: [16]u8 = @splat(0xAA);
    var ctx = testCtx(&buf);

    ctx.store8(0x1010, 0xFF);
    for (buf) |b| try testing.expectEqual(@as(u8, 0xAA), b);
    try testing.expectEqual(FaultKind.store, ctx.fault.kind);
    try testing.expectEqual(@as(u8, 1), ctx.fault.size);
}

test "fetch faults are recorded as fetch" {
    var buf: [16]u8 = @splat(0);
    var ctx = testCtx(&buf);

    _ = ctx.fetchInsn(0x2000);
    try testing.expectEqual(FaultKind.fetch, ctx.fault.kind);
}
