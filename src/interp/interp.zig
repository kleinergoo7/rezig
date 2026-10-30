//! Straight-line interpreter for the P0 integer subset.
//!
//! This is the differential partner of the emitter: it executes the same decoded instructions
//! against `Ctx` directly, so an emitter lowering bug shows up as a state mismatch.

const std = @import("std");
const decode = @import("../ppc/decode.zig");
const ctx_mod = @import("../runtime/ctx.zig");

pub const Error = error{ Unsupported, StepLimit, InvalidUpdate } || std.mem.Allocator.Error;

pub const max_steps: u32 = 4096;

pub fn run(ctx: *ctx_mod.Ctx, words: []const u32) Error!void {
    var steps: u32 = 0;
    for (words) |word| {
        steps += 1;
        if (steps > max_steps) return error.StepLimit;

        const insn = decode.decode(word) catch return error.Unsupported;
        switch (insn) {
            .blr => return,
            .nop => {},
            .addi => |f| ctx.gpr[f.rt] = base(ctx, f.ra) +% sext(f.imm),
            .addis => |f| ctx.gpr[f.rt] = base(ctx, f.ra) +% sext32(f.imm),
            .ori => |f| ctx.gpr[f.rt] = ctx.gpr[f.ra] | f.imm,
            .oris => |f| ctx.gpr[f.rt] = ctx.gpr[f.ra] | (@as(u64, f.imm) << 16),
            .andi_dot => |f| {
                const value = ctx.gpr[f.ra] & f.imm;
                ctx.gpr[f.rt] = value;
                ctx.setCr(0, value, 0, true);
            },
            .or_ => |f| ctx.gpr[f.ra] = ctx.gpr[f.rt] | ctx.gpr[f.rb],
            .add => |f| ctx.gpr[f.rt] = ctx.gpr[f.ra] +% ctx.gpr[f.rb],
            .subf => |f| ctx.gpr[f.rt] = ctx.gpr[f.rb] -% ctx.gpr[f.ra],
            .mullw => |f| ctx.gpr[f.rt] = @truncate(@as(u32, @truncate(ctx.gpr[f.ra])) *% @as(u32, @truncate(ctx.gpr[f.rb]))),
            .srawi => |f| ctx.gpr[f.ra] = sraw32(ctx.gpr[f.rs], f.sh),
            .sraw => |f| ctx.gpr[f.rt] = sraw32(ctx.gpr[f.ra], @truncate(ctx.gpr[f.rb] & 0x3f)),
            .rlwinm => |f| ctx.gpr[f.ra] = std.math.rotl(u32, @truncate(ctx.gpr[f.rs]), f.sh) & mask32(f.mb, f.me),
            .mflr => |f| ctx.gpr[f.rt] = ctx.lr,
            .mtlr => |f| ctx.lr = @truncate(ctx.gpr[f.rt]),
            .mfctr => |f| ctx.gpr[f.rt] = ctx.ctr,
            .mtctr => |f| ctx.ctr = @truncate(ctx.gpr[f.rt]),
            .lwz => |f| ctx.gpr[f.rt] = ctx.load32(addr(ctx, f.ra, f.imm)),
            .lwzu => |f| {
                if (f.ra == 0 or f.ra == f.rt) return error.InvalidUpdate;
                const at = addr(ctx, f.ra, f.imm);
                ctx.gpr[f.rt] = ctx.load32(at);
                ctx.gpr[f.ra] = at;
            },
            .lbz => |f| ctx.gpr[f.rt] = ctx.load8(addr(ctx, f.ra, f.imm)),
            .lbzu => |f| {
                if (f.ra == 0 or f.ra == f.rt) return error.InvalidUpdate;
                const at = addr(ctx, f.ra, f.imm);
                ctx.gpr[f.rt] = ctx.load8(at);
                ctx.gpr[f.ra] = at;
            },
            .stw => |f| ctx.store32(addr(ctx, f.ra, f.imm), ctx.gpr[f.rt]),
            .stwu => |f| {
                if (f.ra == 0) return error.InvalidUpdate;
                const at = addr(ctx, f.ra, f.imm);
                ctx.store32(at, ctx.gpr[f.rt]);
                ctx.gpr[f.ra] = at;
            },
            .stb => |f| ctx.store8(addr(ctx, f.ra, f.imm), ctx.gpr[f.rt]),
            .cmpwi => |f| ctx.setCr(f.crf, ctx.gpr[f.ra], @bitCast(@as(i64, f.imm)), true),
            .cmplwi => |f| ctx.setCr(f.crf, ctx.gpr[f.ra], @as(u64, f.imm), false),
            else => return error.Unsupported,
        }
    }
}

/// PowerPC shift amount is the low 6 bits; 32..63 fill with the sign bit.
fn sraw32(value: u64, shift: u6) u64 {
    const x: i32 = @truncate(@as(i64, @bitCast(value)));
    if (shift >= 32) return @as(u32, @bitCast(x >> 31));
    return @as(u32, @bitCast(x >> @intCast(shift)));
}

fn base(ctx: *const ctx_mod.Ctx, ra: u8) u64 {
    return if (ra == 0) 0 else ctx.gpr[ra];
}

fn addr(ctx: *const ctx_mod.Ctx, ra: u8, imm: i16) u32 {
    return @truncate(base(ctx, ra) +% sext(imm));
}

fn sext(imm: i16) u64 {
    return @bitCast(@as(i64, imm));
}

fn sext32(imm: i16) u64 {
    return @bitCast(@as(i64, imm) << 16);
}

fn mask32(mb: u5, me: u5) u32 {
    var mask: u32 = 0;
    var bit: u6 = 0;
    while (bit < 32) : (bit += 1) {
        const in_range = if (mb <= me) bit >= mb and bit <= me else bit >= mb or bit <= me;
        if (in_range) mask |= @as(u32, 1) << @intCast(bit);
    }
    return mask;
}

const testing = std.testing;

fn runWords(ctx: *ctx_mod.Ctx, words: []const u32) !void {
    try run(ctx, words);
}

test "arithmetic and rotate match the emitter shapes" {
    var buf: [64]u8 = @splat(0);
    var ctx = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });

    // addi r3,r0,1 ; addi r4,r3,2 ; addis r5,r0,1 ; srawi r6,r5,16 ; blr
    try runWords(&ctx, &.{ 0x38600001, 0x38830002, 0x3ca00001, 0x7ca68670, 0x4e800020 });
    try testing.expectEqual(@as(u64, 1), ctx.gpr[3]);
    try testing.expectEqual(@as(u64, 3), ctx.gpr[4]);
    try testing.expectEqual(@as(u64, 0x10000), ctx.gpr[5]);
    try testing.expectEqual(@as(u64, 1), ctx.gpr[6]);
}

test "loads and stores go through the faulting memory helpers" {
    var buf: [64]u8 = @splat(0);
    var ctx = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });

    // addi r3,r0,0x20 ; stw r4,0(r3) ; lwz r5,0(r3) ; blr
    try runWords(&ctx, &.{ 0x38600020, 0x90830000, 0x80a30000, 0x4e800020 });
    try testing.expectEqual(@as(u64, 0), ctx.gpr[5]);
}

test "an unsupported instruction stops with a name" {
    var buf: [16]u8 = @splat(0);
    var ctx = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    try testing.expectError(error.Unsupported, run(&ctx, &.{0xfc22182a}));
}
