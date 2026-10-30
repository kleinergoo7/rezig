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
    /// Instruction budget for generated code. `0` means unlimited.
    budget: u32,
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
            .budget = 0,
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

    /// Sets one 4-bit CR field from an integer compare (LT, GT, EQ, SO=0).
    pub fn setCr(self: *Ctx, crf: u3, a: u64, b: u64, signed: bool) void {
        var field: u32 = 0;
        if (signed) {
            const x: i64 = @bitCast(a);
            const y: i64 = @bitCast(b);
            if (x < y) field |= 0b1000;
            if (x > y) field |= 0b0100;
            if (x == y) field |= 0b0010;
        } else {
            if (a < b) field |= 0b1000;
            if (a > b) field |= 0b0100;
            if (a == b) field |= 0b0010;
        }
        self.writeCrField(crf, field);
    }

    /// `fcmpu`: unordered comparisons clear LT/GT/EQ. XER.SO is not modelled.
    pub fn setCrFloat(self: *Ctx, crf: u3, a: f64, b: f64) void {
        var field: u32 = 0;
        if (!(std.math.isNan(a) or std.math.isNan(b))) {
            if (a < b) field |= 0b1000;
            if (a > b) field |= 0b0100;
            if (a == b) field |= 0b0010;
        }
        self.writeCrField(crf, field);
    }

    fn writeCrField(self: *Ctx, crf: u3, field: u32) void {
        const shift: u5 = @intCast((7 - @as(u32, crf)) * 4);
        const mask: u32 = @as(u32, 0xf) << shift;
        self.cr = (self.cr & ~mask) | (field << shift);
    }

    /// `bc` and `bclr` accept only the nine encodings compilers emit. The
    /// predicate is spelled out per encoding so no bit is guessed.
    pub fn supportedBo(bo: u5) bool {
        return switch (bo) {
            0, 2, 4, 8, 10, 12, 16, 18, 20 => true,
            else => false,
        };
    }

    /// Evaluates a `bc`/`bclr` condition and applies the CTR update.
    /// Requires `supportedBo(bo)`.
    pub fn branch(self: *Ctx, bo: u5, bi: u5) bool {
        const test_ctr = switch (bo) {
            4, 12, 20 => false,
            else => true,
        };
        const test_cr = switch (bo) {
            16, 18, 20 => false,
            else => true,
        };
        const ctr_zero = bo == 2 or bo == 10 or bo == 18;
        const cr_true = bo == 8 or bo == 10 or bo == 12;

        if (test_ctr) {
            self.ctr -%= 1;
            if ((self.ctr == 0) != ctr_zero) return false;
        }
        if (!test_cr) return true;
        const bit_set = self.crBit(bi) == 1;
        return bit_set == cr_true;
    }

    /// CR bit 0 is the most significant bit of CR.
    pub fn crBit(self: *const Ctx, bit: u5) u1 {
        return @truncate(self.cr >> @intCast(31 - bit));
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

test "branch implements every supported BO encoding" {
    var ctx = Ctx.init(.{ .base = 0, .data = &.{} });
    ctx.cr = 0x8000_0000; // CR bit 0 set.

    // bt / bf
    try std.testing.expect(ctx.branch(12, 0));
    try std.testing.expect(!ctx.branch(4, 0));
    // b: always, no CTR change.
    ctx.ctr = 0;
    try std.testing.expect(ctx.branch(20, 0));
    try std.testing.expectEqual(@as(u32, 0), ctx.ctr);
    // bdnz then bdz.
    ctx.ctr = 1;
    try std.testing.expect(!ctx.branch(16, 0));
    ctx.ctr = 1;
    try std.testing.expect(ctx.branch(18, 0));
    // CR set plus CTR.
    ctx.ctr = 2;
    try std.testing.expect(ctx.branch(8, 0));
    ctx.ctr = 2;
    try std.testing.expect(!ctx.branch(0, 0));
    ctx.ctr = 1;
    try std.testing.expect(ctx.branch(10, 0));
    ctx.ctr = 1;
    try std.testing.expect(!ctx.branch(2, 0));
}

test "setCrFloat sets LT, GT, EQ and unordered" {
    var ctx = Ctx.init(.{ .base = 0, .data = &.{} });
    ctx.setCrFloat(2, 1.0, 2.0);
    try std.testing.expectEqual(@as(u1, 1), ctx.crBit(8));
    ctx.setCrFloat(2, 2.0, 1.0);
    try std.testing.expectEqual(@as(u1, 1), ctx.crBit(9));
    ctx.setCrFloat(2, 2.0, 2.0);
    try std.testing.expectEqual(@as(u1, 1), ctx.crBit(10));
    ctx.setCrFloat(2, std.math.nan(f64), 1.0);
    try std.testing.expectEqual(@as(u1, 0), ctx.crBit(8));
    try std.testing.expectEqual(@as(u1, 0), ctx.crBit(9));
    try std.testing.expectEqual(@as(u1, 0), ctx.crBit(10));
}

test "setCr writes the requested field only" {
    var buf: [16]u8 = @splat(0);
    var ctx = testCtx(&buf);

    ctx.setCr(0, 0x1000, 0x1000, false);
    try testing.expectEqual(@as(u32, 0x2000_0000), ctx.cr);

    ctx.setCr(7, 1, 2, true);
    try testing.expectEqual(@as(u32, 0x2000_0008), ctx.cr);
}

test "fetch faults are recorded as fetch" {
    var buf: [16]u8 = @splat(0);
    var ctx = testCtx(&buf);

    _ = ctx.fetchInsn(0x2000);
    try testing.expectEqual(FaultKind.fetch, ctx.fault.kind);
}
