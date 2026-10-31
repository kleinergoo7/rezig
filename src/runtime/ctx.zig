//! Guest context: registers, memory window and the fault slot.

const std = @import("std");
const memory = @import("memory.zig");

pub const FaultKind = enum { none, load, store, fetch, unsupported, trap };

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
    msr: u64,
    fpscr: u32,
    spr: [1024]u64,
    reserve_addr: u32,
    reserve_valid: bool,
    depth: u32,
    /// Instruction budget for generated code. `0` means unlimited.
    budget: u32,
    mem: memory.Memory,
    fault: Fault,

    pub const max_call_depth: u32 = 4096;

    pub fn init(mem: memory.Memory) Ctx {
        return .{
            .gpr = @splat(0),
            .fpr = @splat(0.0),
            .vmx = @splat(@splat(0)),
            .cr = 0,
            .xer = 0,
            .lr = 0,
            .ctr = 0,
            .msr = 0,
            .fpscr = 0,
            .spr = @splat(0),
            .reserve_addr = 0,
            .reserve_valid = false,
            .depth = 0,
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

    pub fn load16br(self: *Ctx, addr: u32) u64 {
        return @byteSwap(@as(u16, @truncate(self.load16(addr))));
    }

    pub fn load32br(self: *Ctx, addr: u32) u64 {
        return @byteSwap(@as(u32, @truncate(self.load32(addr))));
    }

    pub fn store16br(self: *Ctx, addr: u32, value: u64) void {
        self.store16(addr, @byteSwap(@as(u16, @truncate(value))));
    }

    pub fn store32br(self: *Ctx, addr: u32, value: u64) void {
        self.store32(addr, @byteSwap(@as(u32, @truncate(value))));
    }

    /// XER carry bit, PPC bit 29.
    const xer_ca_mask: u32 = 1 << 2;

    pub fn ca(self: *const Ctx) bool {
        return self.xer & xer_ca_mask != 0;
    }

    fn setCa(self: *Ctx, value: bool) void {
        if (value) {
            self.xer |= xer_ca_mask;
        } else {
            self.xer &= ~xer_ca_mask;
        }
    }

    pub fn addic(self: *Ctx, a: u64, imm: i16) u64 {
        const b: u64 = @bitCast(@as(i64, imm));
        const result, const carry = @addWithOverflow(a, b);
        self.setCa(carry != 0);
        return result;
    }

    pub fn addc(self: *Ctx, a: u64, b: u64) u64 {
        const result, const carry = @addWithOverflow(a, b);
        self.setCa(carry != 0);
        return result;
    }

    pub fn adde(self: *Ctx, a: u64, b: u64) u64 {
        const carry: u64 = @intFromBool(self.ca());
        const sum, const carry1 = @addWithOverflow(a, b);
        const result, const carry2 = @addWithOverflow(sum, carry);
        self.setCa(carry1 != 0 or carry2 != 0);
        return result;
    }

    pub fn addme(self: *Ctx, a: u64) u64 {
        const carry: u64 = @intFromBool(self.ca());
        const sum, const carry1 = @addWithOverflow(a, carry);
        const result, const carry2 = @addWithOverflow(sum, std.math.maxInt(u64));
        self.setCa(carry1 != 0 or carry2 != 0);
        return result;
    }

    pub fn addze(self: *Ctx, a: u64) u64 {
        const carry: u64 = @intFromBool(self.ca());
        const result, const overflow = @addWithOverflow(a, carry);
        self.setCa(overflow != 0);
        return result;
    }

    pub fn subfc(self: *Ctx, a: u64, b: u64) u64 {
        const sum, const carry1 = @addWithOverflow(~a, b);
        const result, const carry2 = @addWithOverflow(sum, 1);
        self.setCa(carry1 != 0 or carry2 != 0);
        return result;
    }

    pub fn subfe(self: *Ctx, a: u64, b: u64) u64 {
        const carry: u64 = @intFromBool(self.ca());
        const sum, const carry1 = @addWithOverflow(~a, b);
        const result, const carry2 = @addWithOverflow(sum, carry);
        self.setCa(carry1 != 0 or carry2 != 0);
        return result;
    }

    pub fn subfze(self: *Ctx, a: u64) u64 {
        const carry: u64 = @intFromBool(self.ca());
        const sum, const carry1 = @addWithOverflow(~a, 0);
        const result, const carry2 = @addWithOverflow(sum, carry);
        self.setCa(carry1 != 0 or carry2 != 0);
        return result;
    }

    pub fn subfme(self: *Ctx, a: u64) u64 {
        const carry: u64 = @intFromBool(self.ca());
        const sum, const carry1 = @addWithOverflow(~a, 0);
        const minus_one, const carry2 = @addWithOverflow(sum, carry);
        const result, const carry3 = @addWithOverflow(minus_one, std.math.maxInt(u64));
        self.setCa(carry1 != 0 or carry2 != 0 or carry3 != 0);
        return result;
    }

    pub fn neg(self: *Ctx, a: u64) u64 {
        const result, const borrow = @subWithOverflow(@as(u64, 0), a);
        self.setCa(borrow != 0);
        return result;
    }

    pub fn mulhw(self: *const Ctx, a: u64, b: u64) u64 {
        _ = self;
        const x: i32 = @truncate(@as(i64, @bitCast(a)));
        const y: i32 = @truncate(@as(i64, @bitCast(b)));
        const product: i64 = @as(i64, x) * @as(i64, y);
        return @as(u32, @bitCast(@as(i32, @truncate(product >> 32))));
    }

    pub fn mulhwu(self: *const Ctx, a: u64, b: u64) u64 {
        _ = self;
        const x: u32 = @truncate(a);
        const y: u32 = @truncate(b);
        return (@as(u64, x) * @as(u64, y)) >> 32;
    }

    pub fn mulld(self: *const Ctx, a: u64, b: u64) u64 {
        _ = self;
        return a *% b;
    }

    pub fn mulhd(self: *const Ctx, a: u64, b: u64) u64 {
        _ = self;
        const x: i128 = @as(i64, @bitCast(a));
        const y: i128 = @as(i64, @bitCast(b));
        return @truncate(@as(u128, @bitCast((x * y) >> 64)));
    }

    pub fn mulhdu(self: *const Ctx, a: u64, b: u64) u64 {
        _ = self;
        return @truncate((@as(u128, a) * @as(u128, b)) >> 64);
    }

    pub fn divw(self: *const Ctx, a: u64, b: u64) u64 {
        _ = self;
        const x: i32 = @truncate(@as(i64, @bitCast(a)));
        const y: i32 = @truncate(@as(i64, @bitCast(b)));
        if (y == 0) return 0;
        if (x == std.math.minInt(i32) and y == -1) return @as(u32, @bitCast(x));
        return @as(u32, @bitCast(@divTrunc(x, y)));
    }

    pub fn divwu(self: *const Ctx, a: u64, b: u64) u64 {
        _ = self;
        const x: u32 = @truncate(a);
        const y: u32 = @truncate(b);
        return if (y == 0) 0 else x / y;
    }

    pub fn divdu(self: *const Ctx, a: u64, b: u64) u64 {
        _ = self;
        return if (b == 0) 0 else a / b;
    }

    pub fn divd(self: *const Ctx, a: u64, b: u64) u64 {
        _ = self;
        const x: i64 = @bitCast(a);
        const y: i64 = @bitCast(b);
        if (y == 0) return 0;
        if (x == std.math.minInt(i64) and y == -1) return a;
        return @bitCast(@divTrunc(x, y));
    }

    pub fn slw(self: *const Ctx, a: u64, b: u64) u64 {
        _ = self;
        return @as(u32, @truncate(a)) << @intCast(b & 31);
    }

    pub fn srw(self: *const Ctx, a: u64, b: u64) u64 {
        _ = self;
        return @as(u32, @truncate(a)) >> @intCast(b & 31);
    }

    pub fn sld(self: *const Ctx, a: u64, b: u64) u64 {
        _ = self;
        return a << @intCast(b & 63);
    }

    pub fn srd(self: *const Ctx, a: u64, b: u64) u64 {
        _ = self;
        return a >> @intCast(b & 63);
    }

    pub fn srad(self: *const Ctx, a: u64, b: u64) u64 {
        _ = self;
        const x: i64 = @bitCast(a);
        return @bitCast(x >> @intCast(b & 63));
    }

    pub fn sradi(self: *const Ctx, a: u64, sh: u6) u64 {
        _ = self;
        const x: i64 = @bitCast(a);
        return @bitCast(x >> @intCast(sh));
    }

    pub fn trapIf(self: *Ctx, to: u5, a: u64, b: u64, addr: u32) void {
        const x: i64 = @bitCast(a);
        const y: i64 = @bitCast(b);
        const lt = to & 0x10 != 0 and x < y;
        const gt = to & 0x08 != 0 and x > y;
        const eq = to & 0x04 != 0 and x == y;
        const ltu = to & 0x02 != 0 and a < b;
        const gtu = to & 0x01 != 0 and a > b;
        if (lt or gt or eq or ltu or gtu) self.trap(addr);
    }

    pub fn getSpr(self: *const Ctx, spr: u10) u64 {
        return switch (spr) {
            8 => self.lr,
            9 => self.ctr,
            1 => self.xer,
            else => self.spr[spr],
        };
    }

    pub fn setSpr(self: *Ctx, spr: u10, value: u64) void {
        switch (spr) {
            8 => self.lr = @truncate(value),
            9 => self.ctr = @truncate(value),
            1 => self.xer = @truncate(value),
            else => self.spr[spr] = value,
        }
    }

    pub fn moveToCrf(self: *Ctx, crm: u8, value: u64) void {
        for (0..8) |i| {
            if (crm & (@as(u8, 0x80) >> @intCast(i)) == 0) continue;
            const shift: u5 = @intCast((7 - i) * 4);
            const field: u32 = @truncate(value >> shift);
            self.writeCrField(@intCast(i), field & 0xf);
        }
    }

    pub fn moveFromCrf(self: *const Ctx, crm: u8) u64 {
        var value: u64 = 0;
        for (0..8) |i| {
            if (crm & (@as(u8, 0x80) >> @intCast(i)) == 0) continue;
            const shift: u5 = @intCast((7 - i) * 4);
            const field: u32 = (self.cr >> shift) & 0xf;
            value |= @as(u64, field) << shift;
        }
        return value;
    }

    pub fn lwarx(self: *Ctx, addr: u32) u64 {
        self.reserve_addr = addr;
        self.reserve_valid = true;
        return self.load32(addr);
    }

    pub fn ldarx(self: *Ctx, addr: u32) u64 {
        self.reserve_addr = addr;
        self.reserve_valid = true;
        return self.load64(addr);
    }

    pub fn stwcx(self: *Ctx, addr: u32, value: u64) void {
        const success = self.reserve_valid and self.reserve_addr == addr;
        if (success) self.store32(addr, value);
        self.setCr(0, @intFromBool(!success), 0, true);
        self.reserve_valid = false;
    }

    pub fn stdcx(self: *Ctx, addr: u32, value: u64) void {
        const success = self.reserve_valid and self.reserve_addr == addr;
        if (success) self.store64(addr, value);
        self.setCr(0, @intFromBool(!success), 0, true);
        self.reserve_valid = false;
    }

    pub fn fsel(_: *Ctx, a: f64, b: f64, c: f64) f64 {
        return if (a >= 0 or std.math.isNan(a)) c else b;
    }

    pub fn lvsl(_: *Ctx, addr: u32) [16]u8 {
        var out: [16]u8 = undefined;
        for (0..16) |i| out[i] = @truncate(i * 8 + (addr & 15));
        return out;
    }

    pub fn lvsr(_: *Ctx, addr: u32) [16]u8 {
        var out: [16]u8 = undefined;
        for (0..16) |i| out[i] = @truncate((15 - i) * 8 + (addr & 15));
        return out;
    }

    pub fn lvehx(self: *Ctx, addr: u32) [16]u8 {
        var out: [16]u8 = @splat(0);
        const lane: u32 = (addr >> 1) & 7;
        std.mem.writeInt(u16, out[lane * 2 ..][0..2], @truncate(self.load16(addr)), .big);
        return out;
    }

    pub fn trap(self: *Ctx, addr: u32) void {
        self.fault = .{ .kind = .trap, .addr = addr };
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

    /// `fctidz`: leaves the 64-bit integer bit pattern in the FPR.
    pub fn fctidz(_: *Ctx, value: f64) f64 {
        var result: i64 = std.math.minInt(i64);
        if (std.math.isFinite(value)) {
            const truncated = @trunc(value);
            if (truncated >= -9223372036854775808.0 and truncated < 9223372036854775808.0) {
                result = @intFromFloat(truncated);
            }
        }
        return @bitCast(@as(u64, @bitCast(result)));
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

    pub fn setCrBit(self: *Ctx, bit: u5, value: u1) void {
        const shift: u5 = @intCast(31 - bit);
        const mask: u32 = @as(u32, 1) << shift;
        if (value == 1) {
            self.cr |= mask;
        } else {
            self.cr &= ~mask;
        }
    }

    pub fn crField(self: *const Ctx, crf: u3) u4 {
        return @truncate(self.cr >> @intCast((7 - @as(u32, crf)) * 4));
    }

    pub fn setCrField(self: *Ctx, crf: u3, value: u4) void {
        self.writeCrField(crf, value);
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

    /// Same order as `ppc.decode.VmxKind`; the emitter passes the tag value.
    pub const VmxCmpKind = enum {
        vcmpneb,
        vcmpequd,
        vucmprlb,
        vcmpnezb,
        vcmpneh,
        vcmpequq,
        vcmpnezh,
        vcmpnezw,
        vcmpeqfp,
    };

    pub fn vmxCmp(self: *Ctx, kind: u8, a: [16]u8, b: [16]u8) [16]u8 {
        var out: [16]u8 = @splat(0);
        switch (@as(VmxCmpKind, @fromBackingInt(@intCast(kind)))) {
            .vcmpequq => {
                if (std.mem.eql(u8, &a, &b)) out = @splat(0xFF);
            },
            .vcmpequd => for (0..2) |i| {
                const at = i * 8;
                if (std.mem.eql(u8, a[at..][0..8], b[at..][0..8])) @memset(out[at..][0..8], 0xFF);
            },
            .vcmpeqfp => for (0..4) |i| {
                const at = i * 4;
                const x: f32 = @bitCast(std.mem.readInt(u32, a[at..][0..4], .big));
                const y: f32 = @bitCast(std.mem.readInt(u32, b[at..][0..4], .big));
                if (x == y) @memset(out[at..][0..4], 0xFF);
            },
            .vcmpneb => for (0..16) |i| {
                if (a[i] != b[i]) out[i] = 0xFF;
            },
            .vucmprlb => for (0..16) |i| {
                if (a[i] < b[i]) out[i] = 0xFF;
            },
            .vcmpnezb => for (0..16) |i| {
                if (a[i] != 0) out[i] = 0xFF;
            },
            .vcmpneh => for (0..8) |i| {
                const at = i * 2;
                if (std.mem.readInt(u16, a[at..][0..2], .big) != std.mem.readInt(u16, b[at..][0..2], .big)) @memset(out[at..][0..2], 0xFF);
            },
            .vcmpnezh => for (0..8) |i| {
                const at = i * 2;
                if (std.mem.readInt(u16, a[at..][0..2], .big) != 0) @memset(out[at..][0..2], 0xFF);
            },
            .vcmpnezw => for (0..4) |i| {
                const at = i * 4;
                if (std.mem.readInt(u32, a[at..][0..4], .big) != 0) @memset(out[at..][0..4], 0xFF);
            },
        }
        var all = true;
        var any = false;
        for (out) |byte| {
            if (byte == 0) all = false else any = true;
        }
        const field: u4 = if (all) 0b1000 else if (!any) 0b0010 else 0b0100;
        self.setCrField(6, field);
        return out;
    }

    pub fn vadduwm(_: *Ctx, a: [16]u8, b: [16]u8) [16]u8 {
        var out: [16]u8 = undefined;
        for (0..4) |i| {
            const at = i * 4;
            const x = std.mem.readInt(u32, a[at..][0..4], .big);
            const y = std.mem.readInt(u32, b[at..][0..4], .big);
            std.mem.writeInt(u32, out[at..][0..4], x +% y, .big);
        }
        return out;
    }

    pub fn vdivud(_: *Ctx, a: [16]u8, b: [16]u8) [16]u8 {
        var out: [16]u8 = undefined;
        for (0..2) |i| {
            const at = i * 8;
            const x = std.mem.readInt(u64, a[at..][0..8], .big);
            const y = std.mem.readInt(u64, b[at..][0..8], .big);
            std.mem.writeInt(u64, out[at..][0..8], if (y == 0) 0 else x / y, .big);
        }
        return out;
    }

    pub fn vslb(_: *Ctx, a: [16]u8, b: [16]u8) [16]u8 {
        var out: [16]u8 = undefined;
        for (0..16) |i| out[i] = a[i] << @intCast(b[i] & 7);
        return out;
    }

    pub fn vsel(_: *Ctx, a: [16]u8, b: [16]u8, c: [16]u8) [16]u8 {
        var out: [16]u8 = undefined;
        for (0..16) |i| out[i] = (a[i] & c[i]) | (b[i] & ~c[i]);
        return out;
    }

    pub fn vsldoi(_: *Ctx, a: [16]u8, b: [16]u8, sh: u5) [16]u8 {
        var joined: [32]u8 = undefined;
        @memcpy(joined[0..16], &a);
        @memcpy(joined[16..32], &b);
        return joined[sh..][0..16].*;
    }

    pub fn vnmsubfp(_: *Ctx, a: [16]u8, b: [16]u8, c: [16]u8) [16]u8 {
        var out: [16]u8 = undefined;
        for (0..4) |i| {
            const at = i * 4;
            const x: f32 = @bitCast(std.mem.readInt(u32, a[at..][0..4], .big));
            const y: f32 = @bitCast(std.mem.readInt(u32, b[at..][0..4], .big));
            const z: f32 = @bitCast(std.mem.readInt(u32, c[at..][0..4], .big));
            std.mem.writeInt(u32, out[at..][0..4], @bitCast(-(x * y) + z), .big);
        }
        return out;
    }

    pub fn lvewx(self: *Ctx, addr: u32) [16]u8 {
        var out: [16]u8 = @splat(0);
        const lane: u32 = (addr >> 2) & 3;
        std.mem.writeInt(u32, out[lane * 4 ..][0..4], @truncate(self.load32(addr)), .big);
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

test "carry arithmetic matches ppc" {
    var buf: [64]u8 = @splat(0);
    var ctx = testCtx(&buf);

    try std.testing.expectEqual(@as(u64, 0), ctx.addic(std.math.maxInt(u64), 1));
    try std.testing.expect(ctx.ca());
    try std.testing.expectEqual(@as(u64, 0), ctx.addc(std.math.maxInt(u64), 1));
    try std.testing.expect(ctx.ca());
    try std.testing.expectEqual(@as(u64, 0), ctx.adde(std.math.maxInt(u64), 0));
    try std.testing.expect(ctx.ca());
    try std.testing.expectEqual(@as(u64, 0), ctx.addze(std.math.maxInt(u64)));
    try std.testing.expect(ctx.ca());
    try std.testing.expectEqual(@as(u64, 0), ctx.subfc(0, 0));
    try std.testing.expect(ctx.ca());
    try std.testing.expectEqual(@as(u64, 0), ctx.subfe(0, 0));
    try std.testing.expect(ctx.ca());
    try std.testing.expectEqual(@as(u64, 0), ctx.subfze(0));
    try std.testing.expect(ctx.ca());
    try std.testing.expectEqual(std.math.maxInt(u64), ctx.neg(1));
    try std.testing.expect(ctx.ca());
}

test "multiply, divide and shift helpers" {
    var buf: [64]u8 = @splat(0);
    const ctx = testCtx(&buf);

    try std.testing.expectEqual(@as(u64, 0x40000000), ctx.mulhw(0x80000000, 0x80000000));
    try std.testing.expectEqual(@as(u64, 0xFFFFFFFE), ctx.mulhwu(0xFFFFFFFF, 0xFFFFFFFF));
    try std.testing.expectEqual(@as(u64, 12), ctx.mulld(3, 4));
    try std.testing.expectEqual(@as(u64, 0xFFFFFFFD), ctx.divw(0xFFFFFFFFFFFFFFF9, 2));
    try std.testing.expectEqual(@as(u64, 0xFFFFFFFFFFFFFFFD), ctx.divd(0xFFFFFFFFFFFFFFF9, 2));
    try std.testing.expectEqual(@as(u64, 0x7FFFFFFF), ctx.divwu(0xFFFFFFFF, 2));
    try std.testing.expectEqual(@as(u64, 2), ctx.slw(1, 33));
    try std.testing.expectEqual(@as(u64, 1), ctx.srw(0x80000000, 31));
    try std.testing.expectEqual(@as(u64, 2), ctx.sld(1, 65));
    try std.testing.expectEqual(@as(u64, 1), ctx.srd(0x8000000000000000, 63));
    try std.testing.expectEqual(@as(u64, 0xFFFFFFFF00000000), ctx.sradi(0x8000000000000000, 31));
}

test "trapIf only traps on the selected condition" {
    var buf: [64]u8 = @splat(0);
    var ctx = testCtx(&buf);

    ctx.trapIf(0x04, 5, 5, 0x1000);
    try std.testing.expectEqual(FaultKind.trap, ctx.fault.kind);
    ctx.resetFault();
    ctx.trapIf(0x04, 5, 6, 0x1000);
    try std.testing.expectEqual(FaultKind.none, ctx.fault.kind);
}

test "lwarx and stwcx reserve one word" {
    var buf: [64]u8 = @splat(0);
    var ctx = testCtx(&buf);

    try std.testing.expectEqual(@as(u64, 0), ctx.lwarx(0x1000));
    ctx.stwcx(0x1000, 0x12345678);
    try std.testing.expectEqual(@as(u64, 0x12345678), ctx.load32(0x1000));
    try std.testing.expectEqual(@as(u1, 1), ctx.crBit(2));

    ctx.stwcx(0x1000, 1);
    try std.testing.expectEqual(@as(u1, 0), ctx.crBit(2));
}

test "ocrf moves only the selected fields" {
    var buf: [64]u8 = @splat(0);
    var ctx = testCtx(&buf);

    ctx.moveToCrf(0x80, 0x12345678);
    try std.testing.expectEqual(@as(u32, 0x10000000), ctx.cr);
    try std.testing.expectEqual(@as(u64, 0x10000000), ctx.moveFromCrf(0x80));
    try std.testing.expectEqual(@as(u64, 0), ctx.moveFromCrf(0x40));
}

test "spr moves route lr and ctr" {
    var buf: [64]u8 = @splat(0);
    var ctx = testCtx(&buf);

    ctx.setSpr(1023, 7);
    try std.testing.expectEqual(@as(u64, 7), ctx.getSpr(1023));
    ctx.setSpr(8, 0x1234);
    try std.testing.expectEqual(@as(u32, 0x1234), ctx.lr);
    ctx.setSpr(9, 0x5678);
    try std.testing.expectEqual(@as(u32, 0x5678), ctx.ctr);
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
