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

    /// Sets one CR field from a 32-bit integer compare.
    pub fn setCr32(self: *Ctx, crf: u3, a: u64, b: u64, signed: bool) void {
        if (signed) {
            const x: i64 = @as(i32, @bitCast(@as(u32, @truncate(a))));
            const y: i64 = @as(i32, @bitCast(@as(u32, @truncate(b))));
            self.setCr(crf, @bitCast(x), @bitCast(y), true);
        } else {
            self.setCr(crf, @as(u32, @truncate(a)), @as(u32, @truncate(b)), false);
        }
    }

    /// `fcmpu`: NaN sets the unordered bit (FU). XER.SO is not modelled.
    pub fn setCrFloat(self: *Ctx, crf: u3, a: f64, b: f64) void {
        var field: u32 = 0;
        if (std.math.isNan(a) or std.math.isNan(b)) {
            field |= 0b0001;
        } else {
            if (a < b) field |= 0b1000;
            if (a > b) field |= 0b0100;
            if (a == b) field |= 0b0010;
        }
        self.writeCrField(crf, field);
    }

    /// `fctiwz`: leaves the 32-bit integer bit pattern in the FPR. Out of range
    /// and NaN produce the hardware sentinel 0x80000000.
    pub fn fctiwz(_: *Ctx, value: f64) f64 {
        var result: i32 = -2147483648;
        if (std.math.isFinite(value)) {
            const truncated = @trunc(value);
            if (truncated >= -2147483648.0 and truncated <= 2147483647.0) {
                result = @intFromFloat(truncated);
            }
        }
        return @bitCast(@as(u64, @bitCast(@as(i64, result))));
    }

    fn writeCrField(self: *Ctx, crf: u3, field: u32) void {
        const shift: u5 = @intCast((7 - @as(u32, crf)) * 4);
        const mask: u32 = @as(u32, 0xf) << shift;
        self.cr = (self.cr & ~mask) | (field << shift);
    }

    /// Drop the PowerPC branch-hint bits. A `+` or `-` hint sets one bit
    /// that is otherwise unused by that branch class.
    fn branchBaseBo(bo: u5) u5 {
        return switch (bo) {
            6, 7 => 4,
            14, 15 => 12,
            21 => 20,
            24, 25 => 16,
            26, 27 => 18,
            else => bo,
        };
    }

    /// Evaluates a `bc`/`bclr` condition and applies the CTR update.
    pub fn branch(self: *Ctx, bo_raw: u5, bi: u5) bool {
        const bo = branchBaseBo(bo_raw);
        const test_ctr = bo & 0b00100 == 0;
        const test_cr = bo & 0b10000 == 0;
        const ctr_zero = bo & 0b00010 != 0;
        const cr_true = bo & 0b01000 != 0;

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

    pub fn loadVmx(self: *Ctx, addr: u32) [16]u8 {
        if (!self.mem.contains(addr, 16)) {
            self.recordFault(.load, addr, 16);
            return @splat(0);
        }
        const offset = addr - self.mem.base;
        return self.mem.data[offset..][0..16].*;
    }

    pub fn storeVmx(self: *Ctx, addr: u32, value: [16]u8) void {
        if (!self.mem.contains(addr, 16)) {
            self.recordFault(.store, addr, 16);
            return;
        }
        const offset = addr - self.mem.base;
        @memcpy(self.mem.data[offset..][0..16], &value);
    }

    pub fn vor(_: *Ctx, a: [16]u8, b: [16]u8) [16]u8 {
        return @bitCast(@as(u128, @bitCast(a)) | @as(u128, @bitCast(b)));
    }

    pub fn vxor(_: *Ctx, a: [16]u8, b: [16]u8) [16]u8 {
        return @bitCast(@as(u128, @bitCast(a)) ^ @as(u128, @bitCast(b)));
    }

    pub fn vaddfp(_: *Ctx, a: [16]u8, b: [16]u8) [16]u8 {
        var out: [16]u8 = undefined;
        for (0..4) |i| {
            const at = i * 4;
            const x: f32 = @bitCast(std.mem.readInt(u32, a[at..][0..4], .big));
            const y: f32 = @bitCast(std.mem.readInt(u32, b[at..][0..4], .big));
            std.mem.writeInt(u32, out[at..][0..4], @bitCast(x + y), .big);
        }
        return out;
    }

    pub fn vcmpequb(_: *Ctx, a: [16]u8, b: [16]u8) [16]u8 {
        var out: [16]u8 = @splat(0);
        for (0..16) |i| {
            if (a[i] == b[i]) out[i] = 0xFF;
        }
        return out;
    }

    pub fn vcmpgtub(_: *Ctx, a: [16]u8, b: [16]u8) [16]u8 {
        var out: [16]u8 = @splat(0);
        for (0..16) |i| {
            if (a[i] > b[i]) out[i] = 0xFF;
        }
        return out;
    }

    pub fn vand(_: *Ctx, a: [16]u8, b: [16]u8) [16]u8 {
        return @bitCast(@as(u128, @bitCast(a)) & @as(u128, @bitCast(b)));
    }

    pub fn vsubfp(_: *Ctx, a: [16]u8, b: [16]u8) [16]u8 {
        var out: [16]u8 = undefined;
        for (0..4) |i| {
            const at = i * 4;
            const x: f32 = @bitCast(std.mem.readInt(u32, a[at..][0..4], .big));
            const y: f32 = @bitCast(std.mem.readInt(u32, b[at..][0..4], .big));
            std.mem.writeInt(u32, out[at..][0..4], @bitCast(x - y), .big);
        }
        return out;
    }

    pub fn vrlw(_: *Ctx, a: [16]u8, b: [16]u8) [16]u8 {
        var out: [16]u8 = undefined;
        for (0..4) |i| {
            const at = i * 4;
            const x = std.mem.readInt(u32, a[at..][0..4], .big);
            const sh: u5 = @truncate(std.mem.readInt(u32, b[at..][0..4], .big));
            std.mem.writeInt(u32, out[at..][0..4], std.math.rotl(u32, x, sh), .big);
        }
        return out;
    }

    pub fn vmaddfp(_: *Ctx, a: [16]u8, c: [16]u8, b: [16]u8) [16]u8 {
        var out: [16]u8 = undefined;
        for (0..4) |i| {
            const at = i * 4;
            const x: f32 = @bitCast(std.mem.readInt(u32, a[at..][0..4], .big));
            const y: f32 = @bitCast(std.mem.readInt(u32, c[at..][0..4], .big));
            const z: f32 = @bitCast(std.mem.readInt(u32, b[at..][0..4], .big));
            std.mem.writeInt(u32, out[at..][0..4], @bitCast(@mulAdd(f32, x, y, z)), .big);
        }
        return out;
    }

    pub fn vspltisw(_: *Ctx, simm: i5) [16]u8 {
        const v: u32 = @bitCast(@as(i32, simm));
        var out: [16]u8 = undefined;
        for (0..4) |i| std.mem.writeInt(u32, out[i * 4 ..][0..4], v, .big);
        return out;
    }

    pub fn vperm(_: *Ctx, a: [16]u8, b: [16]u8, c: [16]u8) [16]u8 {
        var out: [16]u8 = undefined;
        for (0..16) |i| {
            const sel = c[i];
            if (sel & 0x20 != 0) {
                out[i] = 0;
            } else {
                const idx = sel & 0x1F;
                if (idx < 16) {
                    out[i] = if (sel & 0x10 != 0) b[idx] else a[idx];
                } else {
                    out[i] = 0;
                }
            }
        }
        return out;
    }

    pub fn sraw32(_: *const Ctx, value: u64, shift: u64) u32 {
        const x: i32 = @bitCast(@as(u32, @truncate(value)));
        const s: u6 = @truncate(shift);
        if (s >= 32) return @bitCast(x >> 31);
        return @bitCast(x >> @as(u5, @truncate(s)));
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

test "branch ignores powerpc hint encodings" {
    var ctx = Ctx.init(.{ .base = 0, .data = &.{} });

    // bdnz+ ignores CR and decrements CTR.
    ctx.ctr = 2;
    ctx.cr = 1 << 31;
    try std.testing.expect(ctx.branch(25, 0));
    try std.testing.expectEqual(@as(u64, 1), ctx.ctr);

    // bdz- branches when CTR reaches zero.
    ctx.ctr = 1;
    try std.testing.expect(ctx.branch(26, 0));
    try std.testing.expectEqual(@as(u64, 0), ctx.ctr);

    // bf+ and bf- test CR bit 0 as false.
    ctx.cr = 0;
    try std.testing.expect(ctx.branch(7, 0));
    try std.testing.expect(ctx.branch(6, 0));
    ctx.cr = 1 << 31;
    try std.testing.expect(!ctx.branch(7, 0));
    try std.testing.expect(!ctx.branch(6, 0));

    // bt+ and bt- test CR bit 0 as true.
    try std.testing.expect(ctx.branch(15, 0));
    try std.testing.expect(ctx.branch(14, 0));

    // b+ is unconditional.
    try std.testing.expect(ctx.branch(21, 0));
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
    try std.testing.expectEqual(@as(u1, 1), ctx.crBit(11));
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

test "vaddfp adds four big-endian f32 lanes" {
    var a: [16]u8 = undefined;
    var b: [16]u8 = undefined;
    for (0..4) |i| {
        std.mem.writeInt(u32, a[i * 4 ..][0..4], @bitCast(@as(f32, @floatFromInt(i + 1))), .big);
        std.mem.writeInt(u32, b[i * 4 ..][0..4], @bitCast(@as(f32, 1.0)), .big);
    }
    const out = Ctx.vaddfp(undefined, a, b);
    for (0..4) |i| {
        const v: f32 = @bitCast(std.mem.readInt(u32, out[i * 4 ..][0..4], .big));
        try std.testing.expectEqual(@as(f32, @floatFromInt(i + 2)), v);
    }
}
