//! Straight-line interpreter for the P0 integer subset.
//!
//! This is the differential partner of the emitter: it executes the same decoded instructions
//! against `Ctx` directly, so an emitter lowering bug shows up as a state mismatch.

const std = @import("std");
const decode = @import("rezig_ppc").decode;
const ctx_mod = @import("rezig_runtime").ctx;

pub const Error = error{ Unsupported, StepLimit, InvalidUpdate, BranchOutOfRange } || std.mem.Allocator.Error;

pub const max_steps: u32 = 1_048_576;

pub const Entry = struct { addr: u32, words: []const u32 };
pub const Table = []const Entry;

pub fn run(ctx: *ctx_mod.Ctx, words: []const u32) Error!void {
    return runTable(ctx, 0, words, &.{});
}

/// Runs `words` starting at `start`, resolving `bl` through `table`. Recursion
/// mirrors the generated code's Zig call stack.
pub fn runTable(ctx: *ctx_mod.Ctx, entry_addr: u32, words: []const u32, table: Table) Error!void {
    var steps: u32 = 0;
    var i: usize = 0;
    while (i < words.len) {
        if (ctx.budget != 0) {
            ctx.budget -= 1;
            if (ctx.budget == 0) return;
        }
        steps += 1;
        if (steps > max_steps) return error.StepLimit;

        const insn = decode.decode(words[i]) catch return error.Unsupported;
        const cur = entry_addr +% @as(u32, @intCast(i)) * 4;
        switch (insn) {
            .blr => return,
            .bl => |f| {
                if (f.absolute) return error.Unsupported;
                const target = cur +% f.target;
                ctx.lr = cur +% 4;
                const callee = lookup(table, target) orelse {
                    ctx.fault = .{ .kind = .unsupported, .addr = target };
                    return;
                };
                try runTable(ctx, target, callee, table);
            },
            .b => |f| {
                if (f.absolute or f.link) return error.Unsupported;
                const target = cur +% f.target;
                if (target >= entry_addr and target < entry_addr +% @as(u32, @intCast(words.len)) * 4) {
                    i = try targetIndex(i, f.target, words.len);
                    continue;
                }
                const callee = lookup(table, target) orelse {
                    ctx.fault = .{ .kind = .unsupported, .addr = target };
                    return;
                };
                try runTable(ctx, target, callee, table);
                return;
            },
            .bc => |f| {
                if (f.absolute or f.link or !ctx_mod.Ctx.supportedBo(f.bo)) return error.Unsupported;
                if (ctx.branch(f.bo, f.bi)) {
                    const target = cur +% f.target;
                    const end = entry_addr +% @as(u32, @intCast(words.len)) * 4;
                    if (target >= entry_addr and target < end) {
                        i = try targetIndex(i, f.target, words.len);
                    } else {
                        const callee = lookup(table, target) orelse {
                            ctx.fault = .{ .kind = .unsupported, .addr = target };
                            return;
                        };
                        try runTable(ctx, target, callee, table);
                        return;
                    }
                } else {
                    i += 1;
                }
                continue;
            },
            .bclr => |f| {
                if (f.absolute or !ctx_mod.Ctx.supportedBo(f.bo)) return error.Unsupported;
                if (f.link) {
                    if (f.bo != 20) return error.Unsupported;
                    const target = ctx.ctr;
                    ctx.lr = cur +% 4;
                    const callee = lookup(table, target) orelse {
                        ctx.fault = .{ .kind = .unsupported, .addr = target };
                        return;
                    };
                    try runTable(ctx, target, callee, table);
                    return;
                }
                if (ctx.branch(f.bo, f.bi)) return;
                i += 1;
                continue;
            },
            .nop => {},
            .addi => |f| ctx.gpr[f.rt] = base(ctx, f.ra) +% sext(f.imm),
            .addis => |f| ctx.gpr[f.rt] = base(ctx, f.ra) +% sext32(f.imm),
            .ori => |f| ctx.gpr[f.ra] = ctx.gpr[f.rt] | f.imm,
            .oris => |f| ctx.gpr[f.ra] = ctx.gpr[f.rt] | (@as(u64, f.imm) << 16),
            .andi_dot => |f| {
                const value = ctx.gpr[f.rt] & f.imm;
                ctx.gpr[f.ra] = value;
                ctx.setCr(0, value, 0, true);
            },
            .or_ => |f| ctx.gpr[f.ra] = ctx.gpr[f.rt] | ctx.gpr[f.rb],
            .add => |f| ctx.gpr[f.rt] = ctx.gpr[f.ra] +% ctx.gpr[f.rb],
            .subf => |f| ctx.gpr[f.rt] = ctx.gpr[f.rb] -% ctx.gpr[f.ra],
            .mullw => |f| ctx.gpr[f.rt] = @truncate(@as(u32, @truncate(ctx.gpr[f.ra])) *% @as(u32, @truncate(ctx.gpr[f.rb]))),
            .srawi => |f| ctx.gpr[f.ra] = sraw32(ctx.gpr[f.rs], f.sh),
            .sraw => |f| ctx.gpr[f.ra] = sraw32(ctx.gpr[f.rt], @truncate(ctx.gpr[f.rb] & 0x3f)),
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
            .ld => |f| ctx.gpr[f.rt] = ctx.load64(dsAddr(ctx, f.ra, f.ds)),
            .ldu => |f| {
                if (f.ra == 0 or f.ra == f.rt) return error.InvalidUpdate;
                const at = dsAddr(ctx, f.ra, f.ds);
                ctx.gpr[f.rt] = ctx.load64(at);
                ctx.gpr[f.ra] = at;
            },
            .lwa => |f| {
                const w = ctx.load32(dsAddr(ctx, f.ra, f.ds));
                ctx.gpr[f.rt] = @as(u64, @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(w)))))));
            },
            .std => |f| ctx.store64(dsAddr(ctx, f.ra, f.ds), ctx.gpr[f.rt]),
            .stdu => |f| {
                if (f.ra == 0) return error.InvalidUpdate;
                const at = dsAddr(ctx, f.ra, f.ds);
                ctx.store64(at, ctx.gpr[f.rt]);
                ctx.gpr[f.ra] = at;
            },
            .cmpw => |f| ctx.setCr(f.crf, ctx.gpr[f.ra], ctx.gpr[f.rb], true),
            .cmplw => |f| ctx.setCr(f.crf, ctx.gpr[f.ra], ctx.gpr[f.rb], false),
            .lwzx => |f| ctx.gpr[f.rt] = ctx.load32(xaddr(ctx, f.ra, f.rb)),
            .lbzx => |f| ctx.gpr[f.rt] = ctx.load8(xaddr(ctx, f.ra, f.rb)),
            .stwx => |f| ctx.store32(xaddr(ctx, f.ra, f.rb), ctx.gpr[f.rt]),
            .mulli => |f| ctx.gpr[f.rt] = @as(u64, @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(ctx.gpr[f.ra])))) *% @as(i32, f.imm)))),
            .extsh => |f| ctx.gpr[f.ra] = @as(u64, @bitCast(@as(i64, @as(i16, @bitCast(@as(u16, @truncate(ctx.gpr[f.rt]))))))),
            .extsb => |f| ctx.gpr[f.ra] = @as(u64, @bitCast(@as(i64, @as(i8, @bitCast(@as(u8, @truncate(ctx.gpr[f.rt]))))))),
            .extsw => |f| ctx.gpr[f.ra] = @as(u64, @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(ctx.gpr[f.rt]))))))),
            .stw => |f| ctx.store32(addr(ctx, f.ra, f.imm), ctx.gpr[f.rt]),
            .stwu => |f| {
                if (f.ra == 0) return error.InvalidUpdate;
                const at = addr(ctx, f.ra, f.imm);
                ctx.store32(at, ctx.gpr[f.rt]);
                ctx.gpr[f.ra] = at;
            },
            .stb => |f| ctx.store8(addr(ctx, f.ra, f.imm), ctx.gpr[f.rt]),
            .lfs => |f| ctx.fpr[f.frd] = @floatCast(@as(f32, @bitCast(@as(u32, @truncate(ctx.load32(addr(ctx, f.ra, f.imm))))))),
            .stfs => |f| ctx.store32(addr(ctx, f.ra, f.imm), @as(u32, @bitCast(@as(f32, @floatCast(ctx.fpr[f.frd]))))),
            .fadd => |f| ctx.fpr[f.frd] = ctx.fpr[f.fra] + ctx.fpr[f.frb],
            .fsub => |f| ctx.fpr[f.frd] = ctx.fpr[f.fra] - ctx.fpr[f.frb],
            .fmul => |f| ctx.fpr[f.frd] = ctx.fpr[f.fra] * ctx.fpr[f.frb],
            .fdiv => |f| ctx.fpr[f.frd] = ctx.fpr[f.fra] / ctx.fpr[f.frb],
            .fcmpu => |f| ctx.setCrFloat(f.crf, ctx.fpr[f.fra], ctx.fpr[f.frb]),
            .fmr => |f| ctx.fpr[f.frd] = ctx.fpr[f.fra],
            .fadds => |f| ctx.fpr[f.frd] = @floatCast(@as(f32, @floatCast(ctx.fpr[f.fra])) + @as(f32, @floatCast(ctx.fpr[f.frb]))),
            .fsubs => |f| ctx.fpr[f.frd] = @floatCast(@as(f32, @floatCast(ctx.fpr[f.fra])) - @as(f32, @floatCast(ctx.fpr[f.frb]))),
            .fmuls => |f| ctx.fpr[f.frd] = @floatCast(@as(f32, @floatCast(ctx.fpr[f.fra])) * @as(f32, @floatCast(ctx.fpr[f.frb]))),
            .fdivs => |f| ctx.fpr[f.frd] = @floatCast(@as(f32, @floatCast(ctx.fpr[f.fra])) / @as(f32, @floatCast(ctx.fpr[f.frb]))),
            .fctiwz => |f| ctx.fpr[f.frd] = @floatFromInt(@as(i32, @intFromFloat(ctx.fpr[f.fra]))),
            .lfd => |f| ctx.fpr[f.frd] = @bitCast(ctx.load64(addr(ctx, f.ra, f.imm))),
            .stfd => |f| ctx.store64(addr(ctx, f.ra, f.imm), @bitCast(ctx.fpr[f.frd])),
            .lvx => |f| ctx.vmx[f.vd] = ctx.loadVmx(vaddr(ctx, f.ra, f.rb)),
            .stvx => |f| ctx.storeVmx(vaddr(ctx, f.ra, f.rb), ctx.vmx[f.vd]),
            .vor => |f| ctx.vmx[f.vd] = ctx.vor(ctx.vmx[f.va], ctx.vmx[f.vb]),
            .vxor => |f| ctx.vmx[f.vd] = ctx.vxor(ctx.vmx[f.va], ctx.vmx[f.vb]),
            .vaddfp => |f| ctx.vmx[f.vd] = ctx.vaddfp(ctx.vmx[f.va], ctx.vmx[f.vb]),
            .cmpwi => |f| ctx.setCr(f.crf, ctx.gpr[f.ra], @bitCast(@as(i64, f.imm)), true),
            .cmplwi => |f| ctx.setCr(f.crf, ctx.gpr[f.ra], @as(u64, f.imm), false),
        }
        i += 1;
    }
}

fn lookup(table: Table, target: u32) ?[]const u32 {
    for (table) |entry| {
        if (entry.addr == target) return entry.words;
    }
    return null;
}

/// Branch fields are byte offsets from the current instruction.
fn targetIndex(current: usize, offset: u32, len: usize) Error!usize {
    const delta: i32 = @bitCast(offset);
    if (@rem(delta, 4) != 0) return error.BranchOutOfRange;
    const next = @as(i64, @intCast(current)) + @divExact(@as(i64, delta), 4);
    if (next < 0 or next >= @as(i64, @intCast(len))) return error.BranchOutOfRange;
    return @intCast(next);
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

fn vaddr(ctx: *const ctx_mod.Ctx, ra: u8, rb: u8) u32 {
    return @truncate(base(ctx, ra) +% ctx.gpr[rb]);
}

fn dsAddr(ctx: *const ctx_mod.Ctx, ra: u8, ds: i16) u32 {
    return @truncate(base(ctx, ra) +% @as(u64, @bitCast(@as(i64, ds))));
}

fn xaddr(ctx: *const ctx_mod.Ctx, ra: u8, rb: u8) u32 {
    return @truncate(base(ctx, ra) +% ctx.gpr[rb]);
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

test "tail call runs the target and returns to the caller" {
    var buf: [16]u8 = @splat(0);
    var ctx = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });

    // 0x1000: addi r3,r0,1 ; b 0x100C
    // 0x100C: addi r3,r3,1 ; blr
    const a = [_]u32{ 0x38600001, 0x48000008 };
    const b = [_]u32{ 0x38630001, 0x4e800020 };
    const table = [_]Entry{
        .{ .addr = 0x1000, .words = &a },
        .{ .addr = 0x100C, .words = &b },
    };
    try runTable(&ctx, 0x1000, &a, &table);
    try testing.expectEqual(@as(u64, 2), ctx.gpr[3]);
}

test "bctrl runs the target in ctr and returns" {
    var buf: [16]u8 = @splat(0);
    var ctx = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    ctx.ctr = 0x2000;

    const a = [_]u32{ 0x4e800421, 0x4e800020 };
    const b = [_]u32{ 0x38600007, 0x4e800020 };
    const table = [_]Entry{
        .{ .addr = 0x1000, .words = &a },
        .{ .addr = 0x2000, .words = &b },
    };
    try runTable(&ctx, 0x1000, &a, &table);
    try testing.expectEqual(@as(u64, 7), ctx.gpr[3]);
}
