//! Straight-line interpreter for the P0 integer subset.
//!
//! This is the differential partner of the emitter: it executes the same decoded instructions
//! against `Ctx` directly, so an emitter lowering bug shows up as a state mismatch.

const std = @import("std");
const decode = @import("rezig_ppc").decode;
const ctx_mod = @import("rezig_runtime").ctx;

pub const Error = error{ Unsupported, StepLimit, InvalidUpdate, BranchOutOfRange } || std.mem.Allocator.Error;

pub const max_steps: u32 = 1_048_576;

/// Temporary boot-path tracer (removed after the pre-import hang is fixed).
/// When enabled, records the last traced pcs in a ring.
pub var dbg_on: bool = false;
pub var dbg_ring: [512]u32 = @splat(0);
pub var dbg_pos: usize = 0;
pub var dbg_total: u64 = 0;
pub var dbg_calls: [512]u32 = @splat(0);
pub var dbg_call_pos: usize = 0;
// TEMP-TRACE: first pc where r1 leaves the image mapping.
pub var dbg_r1_bad: bool = false;

pub const Entry = struct { addr: u32, words: []const u32 };
pub const Table = []const Entry;

pub fn run(ctx: *ctx_mod.Ctx, words: []const u32) Error!void {
    return runTable(ctx, 0, words, &.{});
}

/// Runs `words` starting at `start`, resolving `bl` through `table`. Recursion
/// mirrors the generated code's Zig call stack.
pub fn runTable(ctx: *ctx_mod.Ctx, entry_addr: u32, words: []const u32, table: Table) Error!void {
    if (ctx.depth >= ctx_mod.Ctx.max_call_depth) {
        ctx.fault = .{ .kind = .recursion, .addr = entry_addr };
        return;
    }
    ctx.depth += 1;
    defer ctx.depth -= 1;
    if (dbg_on) {
        dbg_calls[dbg_call_pos % dbg_calls.len] = entry_addr;
        dbg_call_pos +%= 1;
    }
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
        if (dbg_on) {
            dbg_ring[dbg_pos % dbg_ring.len] = cur;
            dbg_pos +%= 1;
            dbg_total += 1;
            if (!dbg_r1_bad and ctx.gpr[1] < 0x82000000) {
                dbg_r1_bad = true;
                std.debug.print("TEMP r1 left image at pc=0x{X} r1=0x{X} lr=0x{X} depth={d}\n", .{ cur, ctx.gpr[1], ctx.lr, ctx.depth });
            }
        }
        const r1_before: u64 = ctx.gpr[31];
        switch (insn) {
            .blr => return,
            .bl => |f| {
                const target = if (f.absolute) f.target else cur +% f.target;
                ctx.lr = cur +% 4;
                // TEMP-TRACE: dump the exception record on RtlRaiseException calls.
                if (dbg_on and target == 0x835A4BCC) {
                    std.debug.print("TEMP raise lr=0x{X} r3=0x{X} r4=0x{X} r5=0x{X}\n", .{ ctx.lr, ctx.gpr[3], ctx.gpr[4], ctx.gpr[5] });
                    var k: u32 = 0;
                    while (k < 8) : (k += 1) {
                        std.debug.print("TEMP rec+{d} = 0x{X}\n", .{ k * 4, ctx.load32(@as(u32, @truncate(ctx.gpr[3])) +% k * 4) });
                    }
                }
                const callee = lookup(table, target) orelse {
                    ctx.fault = .{ .kind = .unsupported, .addr = target };
                    return;
                };
                try runTable(ctx, target, callee, table);
            },
            .b => |f| {
                const target = if (f.absolute) f.target else cur +% f.target;
                const end = entry_addr +% @as(u32, @intCast(words.len)) * 4;
                if (target >= entry_addr and target < end) {
                    i = @intCast((target - entry_addr) / 4);
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
                if (!ctx.branch(f.bo, f.bi)) {
                    i += 1;
                    continue;
                }
                const target = if (f.absolute) f.target else cur +% f.target;
                if (f.link) {
                    ctx.lr = cur +% 4;
                    const callee = lookup(table, target) orelse {
                        ctx.fault = .{ .kind = .unsupported, .addr = target };
                        return;
                    };
                    try runTable(ctx, target, callee, table);
                    i += 1;
                    continue;
                }
                const end = entry_addr +% @as(u32, @intCast(words.len)) * 4;
                if (target >= entry_addr and target < end) {
                    i = @intCast((target - entry_addr) / 4);
                    continue;
                }
                const callee = lookup(table, target) orelse {
                    ctx.fault = .{ .kind = .unsupported, .addr = target };
                    return;
                };
                try runTable(ctx, target, callee, table);
                return;
            },
            .bclr => |f| {
                if (!ctx.branch(f.bo, f.bi)) {
                    i += 1;
                    continue;
                }
                const target = if (f.to_ctr) ctx.ctr else ctx.lr;
                if (f.link) {
                    ctx.lr = cur +% 4;
                    const callee = lookup(table, target) orelse {
                        ctx.fault = .{ .kind = .unsupported, .addr = target };
                        return;
                    };
                    try runTable(ctx, target, callee, table);
                    i += 1;
                    continue;
                }
                if (f.to_ctr) {
                    const callee = lookup(table, target) orelse {
                        ctx.fault = .{ .kind = .unsupported, .addr = target };
                        return;
                    };
                    try runTable(ctx, target, callee, table);
                }
                return;
            },
            .nop, .padding => {},
            .addi => |f| ctx.gpr[f.rt] = base(ctx, f.ra) +% sext(f.imm),
            .addis => |f| ctx.gpr[f.rt] = base(ctx, f.ra) +% sext32(f.imm),
            .ori => |f| ctx.gpr[f.ra] = ctx.gpr[f.rt] | f.imm,
            .oris => |f| ctx.gpr[f.ra] = ctx.gpr[f.rt] | (@as(u64, f.imm) << 16),
            .andi_dot => |f| {
                const value = ctx.gpr[f.rt] & f.imm;
                ctx.gpr[f.ra] = value;
                ctx.setCr(0, value, 0, true);
            },
            .or_ => |f| {
                ctx.gpr[f.ra] = ctx.gpr[f.rt] | ctx.gpr[f.rb];
                recordCr(ctx, f.rc, false, f.ra);
            },
            .add => |f| {
                ctx.gpr[f.rt] = ctx.gpr[f.ra] +% ctx.gpr[f.rb];
                recordCr(ctx, f.rc, false, f.rt);
            },
            .subf => |f| {
                ctx.gpr[f.rt] = ctx.gpr[f.rb] -% ctx.gpr[f.ra];
                recordCr(ctx, f.rc, false, f.rt);
            },
            .mullw => |f| {
                ctx.gpr[f.rt] = @truncate(@as(u32, @truncate(ctx.gpr[f.ra])) *% @as(u32, @truncate(ctx.gpr[f.rb])));
                recordCr(ctx, f.rc, true, f.rt);
            },
            .srawi => |f| {
                ctx.gpr[f.ra] = sraw32(ctx.gpr[f.rs], f.sh);
                recordCr(ctx, f.rc, true, f.ra);
            },
            .sraw => |f| {
                ctx.gpr[f.ra] = sraw32(ctx.gpr[f.rt], @truncate(ctx.gpr[f.rb] & 0x3f));
                recordCr(ctx, f.rc, true, f.ra);
            },
            .rlwinm => |f| {
                ctx.gpr[f.ra] = std.math.rotl(u32, @truncate(ctx.gpr[f.rs]), f.sh) & mask32(f.mb, f.me);
                recordCr(ctx, f.rc, true, f.ra);
            },
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
            .sth => |f| ctx.store16(addr(ctx, f.ra, f.imm), ctx.gpr[f.rt]),
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
            .cmpw => |f| ctx.setCr32(f.crf, ctx.gpr[f.ra], ctx.gpr[f.rb], true),
            .cmplw => |f| ctx.setCr32(f.crf, ctx.gpr[f.ra], ctx.gpr[f.rb], false),
            .lwzx => |f| ctx.gpr[f.rt] = ctx.load32(xaddr(ctx, f.ra, f.rb)),
            .lbzx => |f| ctx.gpr[f.rt] = ctx.load8(xaddr(ctx, f.ra, f.rb)),
            .stwx => |f| ctx.store32(xaddr(ctx, f.ra, f.rb), ctx.gpr[f.rt]),
            .mulli => |f| ctx.gpr[f.rt] = @bitCast(@as(i64, @bitCast(ctx.gpr[f.ra])) *% @as(i64, f.imm)),
            .extsh => |f| {
                ctx.gpr[f.ra] = @as(u64, @bitCast(@as(i64, @as(i16, @bitCast(@as(u16, @truncate(ctx.gpr[f.rt])))))));
                recordCr(ctx, f.rc, true, f.ra);
            },
            .extsb => |f| {
                ctx.gpr[f.ra] = @as(u64, @bitCast(@as(i64, @as(i8, @bitCast(@as(u8, @truncate(ctx.gpr[f.rt])))))));
                recordCr(ctx, f.rc, true, f.ra);
            },
            .extsw => |f| {
                ctx.gpr[f.ra] = @as(u64, @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(ctx.gpr[f.rt])))))));
                recordCr(ctx, f.rc, true, f.ra);
            },
            .and_ => |f| ctx.gpr[f.ra] = ctx.gpr[f.rt] & ctx.gpr[f.rb],
            .frsp => |f| ctx.fpr[f.frd] = @floatCast(@as(f32, @floatCast(ctx.fpr[f.frb]))),
            .fneg => |f| ctx.fpr[f.frd] = -ctx.fpr[f.frb],
            .fcfid => |f| ctx.fpr[f.frd] = @floatFromInt(@as(i64, @bitCast(ctx.fpr[f.frb]))),
            .xori => |f| ctx.gpr[f.ra] = ctx.gpr[f.rt] ^ f.imm,
            .subfic => |f| ctx.gpr[f.ra] = @as(u64, @bitCast(@as(i64, f.imm))) -% ctx.gpr[f.rt],
            .rldicr => |f| ctx.gpr[f.ra] = std.math.rotl(u64, ctx.gpr[f.rs], f.sh) & rldicrMask(f.me),
            .stfiwx => |f| ctx.store32(xaddr(ctx, f.ra, f.rb), @as(u32, @truncate(@as(u64, @bitCast(ctx.fpr[f.rt]))))),
            .cntlzw => |f| {
                ctx.gpr[f.ra] = @clz(@as(u32, @truncate(ctx.gpr[f.rt])));
                recordCr(ctx, f.rc, true, f.ra);
            },
            .stbx => |f| ctx.store8(xaddr(ctx, f.ra, f.rb), ctx.gpr[f.rt]),
            .lfsx => |f| ctx.fpr[f.frd] = @floatCast(@as(f32, @bitCast(@as(u32, @truncate(ctx.load32(xaddr(ctx, f.fra, f.frb))))))),
            .lhz => |f| ctx.gpr[f.rt] = ctx.load16(addr(ctx, f.ra, f.imm)),
            .rlwimi => |f| {
                const mask = mask32(f.mb, f.me);
                const old: u32 = @truncate(ctx.gpr[f.ra]);
                ctx.gpr[f.ra] = (old & ~mask) | (std.math.rotl(u32, @truncate(ctx.gpr[f.rs]), f.sh) & mask);
                recordCr(ctx, f.rc, true, f.ra);
            },
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
            .fmr => |f| ctx.fpr[f.frd] = ctx.fpr[f.frb],
            .fadds => |f| ctx.fpr[f.frd] = @floatCast(@as(f32, @floatCast(ctx.fpr[f.fra])) + @as(f32, @floatCast(ctx.fpr[f.frb]))),
            .fsubs => |f| ctx.fpr[f.frd] = @floatCast(@as(f32, @floatCast(ctx.fpr[f.fra])) - @as(f32, @floatCast(ctx.fpr[f.frb]))),
            .fmuls => |f| ctx.fpr[f.frd] = @floatCast(@as(f32, @floatCast(ctx.fpr[f.fra])) * @as(f32, @floatCast(ctx.fpr[f.frb]))),
            .fdivs => |f| ctx.fpr[f.frd] = @floatCast(@as(f32, @floatCast(ctx.fpr[f.fra])) / @as(f32, @floatCast(ctx.fpr[f.frb]))),
            .fmadds => |f| ctx.fpr[f.frd] = @floatCast(@as(f32, @floatCast(ctx.fpr[f.fra])) * @as(f32, @floatCast(ctx.fpr[f.frc])) + @as(f32, @floatCast(ctx.fpr[f.frb]))),
            .fctiwz => |f| ctx.fpr[f.frd] = ctx.fctiwz(ctx.fpr[f.frb]),
            .fctidz => |f| ctx.fpr[f.frd] = ctx.fctidz(ctx.fpr[f.frb]),
            .fabs => |f| ctx.fpr[f.frd] = @abs(ctx.fpr[f.frb]),
            .fnabs => |f| ctx.fpr[f.frd] = -@abs(ctx.fpr[f.frb]),
            .mffs => |f| ctx.fpr[f.frd] = @bitCast(@as(u64, ctx.fpscr)),
            .mtfsf => |f| ctx.fpscr = @truncate(@as(u64, @bitCast(ctx.fpr[f.frb]))),
            .fsqrt => |f| ctx.fpr[f.frd] = @sqrt(ctx.fpr[f.frb]),
            .fsel => |f| ctx.fpr[f.frd] = ctx.fsel(ctx.fpr[f.fra], ctx.fpr[f.frb], ctx.fpr[f.frc]),
            .fctid => |f| ctx.fpr[f.frd] = ctx.fctidz(ctx.fpr[f.frb]),
            .fsqrts => |f| ctx.fpr[f.frd] = @floatCast(@sqrt(@as(f32, @floatCast(ctx.fpr[f.frb])))),
            .fmsubs => |f| ctx.fpr[f.frd] = @floatCast(@as(f32, @floatCast(ctx.fpr[f.fra])) * @as(f32, @floatCast(ctx.fpr[f.frc])) - @as(f32, @floatCast(ctx.fpr[f.frb]))),
            .fnmsubs => |f| ctx.fpr[f.frd] = @floatCast(-(@as(f32, @floatCast(ctx.fpr[f.fra])) * @as(f32, @floatCast(ctx.fpr[f.frc])) - @as(f32, @floatCast(ctx.fpr[f.frb])))),
            .fnmadds => |f| ctx.fpr[f.frd] = @floatCast(-(@as(f32, @floatCast(ctx.fpr[f.fra])) * @as(f32, @floatCast(ctx.fpr[f.frc])) + @as(f32, @floatCast(ctx.fpr[f.frb])))),
            .fmadd => |f| ctx.fpr[f.frd] = ctx.fpr[f.fra] * ctx.fpr[f.frc] + ctx.fpr[f.frb],
            .fmsub => |f| ctx.fpr[f.frd] = ctx.fpr[f.fra] * ctx.fpr[f.frc] - ctx.fpr[f.frb],
            .fnmsub => |f| ctx.fpr[f.frd] = -(ctx.fpr[f.fra] * ctx.fpr[f.frc] - ctx.fpr[f.frb]),
            .fnmadd => |f| ctx.fpr[f.frd] = -(ctx.fpr[f.fra] * ctx.fpr[f.frc] + ctx.fpr[f.frb]),
            .lfsu => |f| {
                const at = addr(ctx, f.ra, f.imm);
                ctx.fpr[f.frd] = @floatCast(@as(f32, @bitCast(@as(u32, @truncate(ctx.load32(at))))));
                ctx.gpr[f.ra] = at;
            },
            .lfsux => |f| {
                if (f.fra == 0) return error.InvalidUpdate;
                const at = vaddr(ctx, f.fra, f.frb);
                ctx.fpr[f.frd] = @floatCast(@as(f32, @bitCast(@as(u32, @truncate(ctx.load32(at))))));
                ctx.gpr[f.fra] = at;
            },
            .stfsu => |f| {
                const at = addr(ctx, f.ra, f.imm);
                ctx.store32(at, @as(u32, @bitCast(@as(f32, @floatCast(ctx.fpr[f.frd])))));
                ctx.gpr[f.ra] = at;
            },
            .lfdu => |f| {
                const at = addr(ctx, f.ra, f.imm);
                ctx.fpr[f.frd] = @bitCast(ctx.load64(at));
                ctx.gpr[f.ra] = at;
            },
            .stfdu => |f| {
                const at = addr(ctx, f.ra, f.imm);
                ctx.store64(at, @bitCast(ctx.fpr[f.frd]));
                ctx.gpr[f.ra] = at;
            },
            .lfdx => |f| ctx.fpr[f.frd] = @bitCast(ctx.load64(vaddr(ctx, f.fra, f.frb))),
            .lfdux => |f| {
                if (f.fra == 0) return error.InvalidUpdate;
                const at = vaddr(ctx, f.fra, f.frb);
                ctx.fpr[f.frd] = @bitCast(ctx.load64(at));
                ctx.gpr[f.fra] = at;
            },
            .stfsx => |f| ctx.store32(vaddr(ctx, f.fra, f.frb), @as(u32, @bitCast(@as(f32, @floatCast(ctx.fpr[f.frd]))))),
            .stfdx => |f| ctx.store64(vaddr(ctx, f.fra, f.frb), @bitCast(ctx.fpr[f.frd])),
            .lfd => |f| ctx.fpr[f.frd] = @bitCast(ctx.load64(addr(ctx, f.ra, f.imm))),
            .stfd => |f| ctx.store64(addr(ctx, f.ra, f.imm), @bitCast(ctx.fpr[f.frd])),
            .lvx => |f| ctx.vmx[f.vd] = ctx.loadVmx(vaddr(ctx, f.ra, f.rb)),
            .stvx => |f| ctx.storeVmx(vaddr(ctx, f.ra, f.rb), ctx.vmx[f.vd]),
            .lvewx => |f| ctx.vmx[f.vd] = ctx.lvewx(vaddr(ctx, f.ra, f.rb)),
            .lvehx => |f| ctx.vmx[f.vd] = ctx.lvehx(vaddr(ctx, f.ra, f.rb)),
            .lvsl => |f| ctx.vmx[f.vd] = ctx.lvsl(vaddr(ctx, f.ra, f.rb)),
            .lvsr => |f| ctx.vmx[f.vd] = ctx.lvsr(vaddr(ctx, f.ra, f.rb)),
            .vmx => |f| {
                switch (f.kind) {
                    .vcmpequq, .vcmpequd, .vcmpeqfp, .vcmpneb, .vucmprlb, .vcmpnezb, .vcmpneh, .vcmpnezh, .vcmpnezw => {
                        ctx.vmx[f.vd] = ctx.vmxCmp(@backingInt(f.kind), ctx.vmx[f.va], ctx.vmx[f.vb]);
                    },
                    .vadduwm => ctx.vmx[f.vd] = ctx.vadduwm(ctx.vmx[f.va], ctx.vmx[f.vb]),
                    .vdivud => ctx.vmx[f.vd] = ctx.vdivud(ctx.vmx[f.va], ctx.vmx[f.vb]),
                    .vslb => ctx.vmx[f.vd] = ctx.vslb(ctx.vmx[f.va], ctx.vmx[f.vb]),
                    .vsel => ctx.vmx[f.vd] = ctx.vsel(ctx.vmx[f.va], ctx.vmx[f.vb], ctx.vmx[f.vc]),
                    .vsldoi => ctx.vmx[f.vd] = ctx.vsldoi(ctx.vmx[f.va], ctx.vmx[f.vb], @truncate(f.imm)),
                    .vnmsubfp => ctx.vmx[f.vd] = ctx.vnmsubfp(ctx.vmx[f.va], ctx.vmx[f.vb], ctx.vmx[f.vc]),
                }
            },
            .vor => |f| ctx.vmx[f.vd] = ctx.vor(ctx.vmx[f.va], ctx.vmx[f.vb]),
            .vxor => |f| ctx.vmx[f.vd] = ctx.vxor(ctx.vmx[f.va], ctx.vmx[f.vb]),
            .vaddfp => |f| ctx.vmx[f.vd] = ctx.vaddfp(ctx.vmx[f.va], ctx.vmx[f.vb]),
            .vcmpequb => |f| ctx.vmx[f.vd] = ctx.vcmpequb(ctx.vmx[f.va], ctx.vmx[f.vb]),
            .vcmpgtub => |f| ctx.vmx[f.vd] = ctx.vcmpgtub(ctx.vmx[f.va], ctx.vmx[f.vb]),
            .vand => |f| ctx.vmx[f.vd] = ctx.vand(ctx.vmx[f.va], ctx.vmx[f.vb]),
            .vsubfp => |f| ctx.vmx[f.vd] = ctx.vsubfp(ctx.vmx[f.va], ctx.vmx[f.vb]),
            .vrlw => |f| ctx.vmx[f.vd] = ctx.vrlw(ctx.vmx[f.va], ctx.vmx[f.vb]),
            .vperm => |f| ctx.vmx[f.vd] = ctx.vperm(ctx.vmx[f.va], ctx.vmx[f.vb], ctx.vmx[f.vc]),
            .vmaddfp => |f| ctx.vmx[f.vd] = ctx.vmaddfp(ctx.vmx[f.va], ctx.vmx[f.vc], ctx.vmx[f.vb]),
            .vspltisw => |f| ctx.vmx[f.vd] = ctx.vspltisw(f.simm),
            .cmpwi => |f| ctx.setCr32(f.crf, ctx.gpr[f.ra], @bitCast(@as(i64, f.imm)), true),
            .cmplwi => |f| ctx.setCr32(f.crf, ctx.gpr[f.ra], @as(u64, f.imm), false),
            .addic => |f| {
                ctx.gpr[f.rt] = ctx.addic(base(ctx, f.ra), f.imm);
                recordCr(ctx, f.rc, false, f.rt);
            },
            .addc => |f| {
                ctx.gpr[f.rt] = ctx.addc(ctx.gpr[f.ra], ctx.gpr[f.rb]);
                recordCr(ctx, f.rc, false, f.rt);
            },
            .adde => |f| {
                ctx.gpr[f.rt] = ctx.adde(ctx.gpr[f.ra], ctx.gpr[f.rb]);
                recordCr(ctx, f.rc, false, f.rt);
            },
            .addze => |f| {
                ctx.gpr[f.rt] = ctx.addze(ctx.gpr[f.ra]);
                recordCr(ctx, f.rc, false, f.rt);
            },
            .addme => |f| {
                ctx.gpr[f.rt] = ctx.addme(ctx.gpr[f.ra]);
                recordCr(ctx, f.rc, false, f.rt);
            },
            .subfc => |f| {
                ctx.gpr[f.rt] = ctx.subfc(ctx.gpr[f.ra], ctx.gpr[f.rb]);
                recordCr(ctx, f.rc, false, f.rt);
            },
            .subfe => |f| {
                ctx.gpr[f.rt] = ctx.subfe(ctx.gpr[f.ra], ctx.gpr[f.rb]);
                recordCr(ctx, f.rc, false, f.rt);
            },
            .subfme => |f| {
                ctx.gpr[f.rt] = ctx.subfme(ctx.gpr[f.ra]);
                recordCr(ctx, f.rc, false, f.rt);
            },
            .subfze => |f| {
                ctx.gpr[f.rt] = ctx.subfze(ctx.gpr[f.ra]);
                recordCr(ctx, f.rc, false, f.rt);
            },
            .neg => |f| {
                ctx.gpr[f.rt] = ctx.neg(ctx.gpr[f.ra]);
                recordCr(ctx, f.rc, false, f.rt);
            },
            .mulhw => |f| {
                ctx.gpr[f.rt] = ctx.mulhw(ctx.gpr[f.ra], ctx.gpr[f.rb]);
                recordCr(ctx, f.rc, false, f.rt);
            },
            .mulhwu => |f| {
                ctx.gpr[f.rt] = ctx.mulhwu(ctx.gpr[f.ra], ctx.gpr[f.rb]);
                recordCr(ctx, f.rc, false, f.rt);
            },
            .mulld => |f| {
                ctx.gpr[f.rt] = ctx.mulld(ctx.gpr[f.ra], ctx.gpr[f.rb]);
                recordCr(ctx, f.rc, false, f.rt);
            },
            .mulhd => |f| {
                ctx.gpr[f.rt] = ctx.mulhd(ctx.gpr[f.ra], ctx.gpr[f.rb]);
                recordCr(ctx, f.rc, false, f.rt);
            },
            .mulhdu => |f| {
                ctx.gpr[f.rt] = ctx.mulhdu(ctx.gpr[f.ra], ctx.gpr[f.rb]);
                recordCr(ctx, f.rc, false, f.rt);
            },
            .divw => |f| {
                ctx.gpr[f.rt] = ctx.divw(ctx.gpr[f.ra], ctx.gpr[f.rb]);
                recordCr(ctx, f.rc, false, f.rt);
            },
            .divwu => |f| {
                ctx.gpr[f.rt] = ctx.divwu(ctx.gpr[f.ra], ctx.gpr[f.rb]);
                recordCr(ctx, f.rc, false, f.rt);
            },
            .divd => |f| {
                ctx.gpr[f.rt] = ctx.divd(ctx.gpr[f.ra], ctx.gpr[f.rb]);
                recordCr(ctx, f.rc, false, f.rt);
            },
            .divdu => |f| {
                ctx.gpr[f.rt] = ctx.divdu(ctx.gpr[f.ra], ctx.gpr[f.rb]);
                recordCr(ctx, f.rc, false, f.rt);
            },
            .rlwnm => |f| {
                ctx.gpr[f.ra] = std.math.rotl(u32, @truncate(ctx.gpr[f.rs]), @as(u5, @truncate(ctx.gpr[f.rb]))) & mask32(f.mb, f.me);
                recordCr(ctx, f.rc, true, f.ra);
            },
            .slw => |f| ctx.gpr[f.ra] = ctx.slw(ctx.gpr[f.rt], ctx.gpr[f.rb]),
            .srw => |f| ctx.gpr[f.ra] = ctx.srw(ctx.gpr[f.rt], ctx.gpr[f.rb]),
            .sld => |f| ctx.gpr[f.ra] = ctx.sld(ctx.gpr[f.rt], ctx.gpr[f.rb]),
            .srd => |f| ctx.gpr[f.ra] = ctx.srd(ctx.gpr[f.rt], ctx.gpr[f.rb]),
            .srad => |f| ctx.gpr[f.ra] = ctx.srad(ctx.gpr[f.rt], ctx.gpr[f.rb]),
            .sradi => |f| {
                ctx.gpr[f.ra] = ctx.sradi(ctx.gpr[f.rs], f.sh);
                recordCr(ctx, f.rc, false, f.ra);
            },
            .xor_ => |f| ctx.gpr[f.ra] = ctx.gpr[f.rt] ^ ctx.gpr[f.rb],
            .andc => |f| ctx.gpr[f.ra] = ctx.gpr[f.rt] & ~ctx.gpr[f.rb],
            .eqv => |f| ctx.gpr[f.ra] = ~(ctx.gpr[f.rt] ^ ctx.gpr[f.rb]),
            .nor_ => |f| ctx.gpr[f.ra] = ~(ctx.gpr[f.rt] | ctx.gpr[f.rb]),
            .orc => |f| ctx.gpr[f.ra] = ctx.gpr[f.rt] | ~ctx.gpr[f.rb],
            .nand => |f| ctx.gpr[f.ra] = ~(ctx.gpr[f.rt] & ctx.gpr[f.rb]),
            .cntlzd => |f| ctx.gpr[f.ra] = @clz(ctx.gpr[f.rt]),
            .cmpd => |f| ctx.setCr(f.crf, ctx.gpr[f.ra], ctx.gpr[f.rb], true),
            .cmpld => |f| ctx.setCr(f.crf, ctx.gpr[f.ra], ctx.gpr[f.rb], false),
            .twi => |f| ctx.trapIf(f.to, ctx.gpr[f.ra], @bitCast(@as(i64, f.imm)), cur),
            .tw => |f| ctx.trapIf(f.to, ctx.gpr[f.ra], ctx.gpr[f.rb], cur),
            .mfspr => |f| ctx.gpr[f.rt] = ctx.getSpr(f.spr),
            .mftb => |f| ctx.gpr[f.rt] = ctx.getSpr(f.spr),
            .mtspr => |f| ctx.setSpr(f.spr, ctx.gpr[f.rt]),
            .mfmsr => |f| ctx.gpr[f.rt] = ctx.msr,
            .mtmsr => |f| ctx.msr = ctx.gpr[f.rt],
            .mtmsrd => |f| ctx.msr = ctx.gpr[f.rt],
            .mtocrf => |f| ctx.moveToCrf(f.crm, ctx.gpr[f.rt]),
            .mfocrf => |f| ctx.gpr[f.rt] = ctx.moveFromCrf(f.crm),
            .lwsync, .sync, .isync, .eieio, .dcbt, .dcbtst, .dcbf, .dcbst, .dcbz, .icbi, .tlbiel, .tlbie, .slbmte, .slbia => {},
            .lwarx => |f| ctx.gpr[f.rt] = ctx.lwarx(vaddr(ctx, f.ra, f.rb)),
            .ldarx => |f| ctx.gpr[f.rt] = ctx.ldarx(vaddr(ctx, f.ra, f.rb)),
            .stwcx => |f| ctx.stwcx(vaddr(ctx, f.ra, f.rb), ctx.gpr[f.rt]),
            .stdcx => |f| ctx.stdcx(vaddr(ctx, f.ra, f.rb), ctx.gpr[f.rt]),
            .lhzu => |f| {
                if (f.ra == 0 or f.ra == f.rt) return error.InvalidUpdate;
                const at = addr(ctx, f.ra, f.imm);
                ctx.gpr[f.rt] = ctx.load16(at);
                ctx.gpr[f.ra] = at;
            },
            .lhzux => |f| {
                if (f.ra == 0 or f.ra == f.rt) return error.InvalidUpdate;
                const at = vaddr(ctx, f.ra, f.rb);
                ctx.gpr[f.rt] = ctx.load16(at);
                ctx.gpr[f.ra] = at;
            },
            .lha => |f| {
                const w = ctx.load16(addr(ctx, f.ra, f.imm));
                ctx.gpr[f.rt] = @bitCast(@as(i64, @as(i16, @bitCast(@as(u16, @truncate(w))))));
            },
            .lhau => |f| {
                if (f.ra == 0 or f.ra == f.rt) return error.InvalidUpdate;
                const at = addr(ctx, f.ra, f.imm);
                const w = ctx.load16(at);
                ctx.gpr[f.rt] = @bitCast(@as(i64, @as(i16, @bitCast(@as(u16, @truncate(w))))));
                ctx.gpr[f.ra] = at;
            },
            .stbu => |f| ctx.store8(addr(ctx, f.ra, f.imm), ctx.gpr[f.rt]),
            .sthu => |f| ctx.store16(addr(ctx, f.ra, f.imm), ctx.gpr[f.rt]),
            .sthx => |f| ctx.store16(vaddr(ctx, f.ra, f.rb), ctx.gpr[f.rt]),
            .ldx => |f| ctx.gpr[f.rt] = ctx.load64(vaddr(ctx, f.ra, f.rb)),
            .stdx => |f| ctx.store64(vaddr(ctx, f.ra, f.rb), ctx.gpr[f.rt]),
            .lwzux => |f| {
                if (f.ra == 0 or f.ra == f.rt) return error.InvalidUpdate;
                const at = vaddr(ctx, f.ra, f.rb);
                ctx.gpr[f.rt] = ctx.load32(at);
                ctx.gpr[f.ra] = at;
            },
            .lwax => |f| {
                const w = ctx.load32(vaddr(ctx, f.ra, f.rb));
                ctx.gpr[f.rt] = @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(w))))));
            },
            .stwux => |f| {
                if (f.ra == 0) return error.InvalidUpdate;
                const at = vaddr(ctx, f.ra, f.rb);
                ctx.store32(at, ctx.gpr[f.rt]);
                ctx.gpr[f.ra] = at;
            },
            .sthux => |f| {
                if (f.ra == 0) return error.InvalidUpdate;
                const at = vaddr(ctx, f.ra, f.rb);
                ctx.store16(at, ctx.gpr[f.rt]);
                ctx.gpr[f.ra] = at;
            },
            .stdux => |f| {
                if (f.ra == 0) return error.InvalidUpdate;
                const at = vaddr(ctx, f.ra, f.rb);
                ctx.store64(at, ctx.gpr[f.rt]);
                ctx.gpr[f.ra] = at;
            },
            .stbux => |f| {
                if (f.ra == 0) return error.InvalidUpdate;
                const at = vaddr(ctx, f.ra, f.rb);
                ctx.store8(at, ctx.gpr[f.rt]);
                ctx.gpr[f.ra] = at;
            },
            .lbzux => |f| {
                if (f.ra == 0 or f.ra == f.rt) return error.InvalidUpdate;
                const at = vaddr(ctx, f.ra, f.rb);
                ctx.gpr[f.rt] = ctx.load8(at);
                ctx.gpr[f.ra] = at;
            },
            .lwbrx => |f| ctx.gpr[f.rt] = ctx.load32br(vaddr(ctx, f.ra, f.rb)),
            .lhbrx => |f| ctx.gpr[f.rt] = ctx.load16br(vaddr(ctx, f.ra, f.rb)),
            .lhax => |f| {
                const w = ctx.load16(vaddr(ctx, f.ra, f.rb));
                ctx.gpr[f.rt] = @bitCast(@as(i64, @as(i16, @bitCast(@as(u16, @truncate(w))))));
            },
            .lhaux => |f| {
                if (f.ra == 0 or f.ra == f.rt) return error.InvalidUpdate;
                const at = vaddr(ctx, f.ra, f.rb);
                const w = ctx.load16(at);
                ctx.gpr[f.rt] = @bitCast(@as(i64, @as(i16, @bitCast(@as(u16, @truncate(w))))));
                ctx.gpr[f.ra] = at;
            },
            .stwbrx => |f| ctx.store32br(vaddr(ctx, f.ra, f.rb), ctx.gpr[f.rt]),
            .sthbrx => |f| ctx.store16br(vaddr(ctx, f.ra, f.rb), ctx.gpr[f.rt]),
            .xoris => |f| ctx.gpr[f.ra] = ctx.gpr[f.rt] ^ (@as(u64, f.imm) << 16),
            .andis_dot => |f| {
                ctx.gpr[f.ra] = ctx.gpr[f.rt] & (@as(u64, f.imm) << 16);
                ctx.setCr(0, ctx.gpr[f.ra], 0, true);
            },
            .cr_op => |f| {
                const a = ctx.crBit(f.ba);
                const b = ctx.crBit(f.bb);
                const value: u1 = switch (f.kind) {
                    .crand => a & b,
                    .crandc => a & ~b,
                    .creqv => ~(a ^ b),
                    .crnand => ~(a & b),
                    .crnor => ~(a | b),
                    .cror => a | b,
                    .crorc => a | ~b,
                    .crxor => a ^ b,
                };
                ctx.setCrBit(f.bt, value);
            },
            .mcrf => |f| ctx.setCrField(f.crf_d, ctx.crField(f.crf_s)),
            .rfid => {
                ctx.msr = ctx.getSpr(27);
                const target: u32 = @truncate(ctx.getSpr(26));
                const end = entry_addr +% @as(u32, @intCast(words.len)) * 4;
                if (target >= entry_addr and target < end) {
                    i = @intCast((target - entry_addr) / 4);
                    continue;
                }
                return;
            },
        }
        // TEMP-TRACE: catch the exact instruction that corrupts r1.
        if (dbg_on and !dbg_r1_bad and r1_before >= 0x82000000 and ctx.gpr[31] != r1_before) {
            std.debug.print("TEMP r31 write at pc=0x{X} 0x{X} -> 0x{X} lr=0x{X} depth={d}\n", .{ cur, r1_before, ctx.gpr[31], ctx.lr, ctx.depth });
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

/// PowerPC shift amount is the low 6 bits; 32..63 fill with the sign bit.
fn sraw32(value: u64, shift: u6) u64 {
    const x: i32 = @truncate(@as(i64, @bitCast(value)));
    if (shift >= 32) return @as(u32, @bitCast(x >> 31));
    return @as(u32, @bitCast(x >> @intCast(shift)));
}

fn recordCr(ctx: *ctx_mod.Ctx, rc: bool, is_32: bool, reg: u8) void {
    if (!rc) return;
    if (is_32) {
        ctx.setCr32(0, ctx.gpr[reg], 0, true);
    } else {
        ctx.setCr(0, ctx.gpr[reg], 0, true);
    }
}

fn rldicrMask(me: u6) u64 {
    if (me == 63) return 0xFFFFFFFFFFFFFFFF;
    return ~((@as(u64, 1) << @intCast(63 - @as(u6, me))) - 1);
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
        const ppc_bit: u6 = 31 - bit;
        const in_range = if (mb <= me) ppc_bit >= mb and ppc_bit <= me else ppc_bit >= mb or ppc_bit <= me;
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

test "fmul and fmadd read the right operands" {
    var buf: [16]u8 = @splat(0);

    var mul = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    mul.fpr[1] = 3;
    mul.fpr[12] = 4;
    try runWords(&mul, &.{ 0xFC210332, 0x4e800020 }); // fmul f1,f1,f12
    try testing.expectEqual(@as(f64, 12), mul.fpr[1]);

    var add = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    add.fpr[1] = 2;
    add.fpr[0] = 3;
    add.fpr[9] = 4;
    try runWords(&add, &.{ 0xFC21483A, 0x4e800020 }); // fmadd f1,f1,f0,f9
    try testing.expectEqual(@as(f64, 10), add.fpr[1]);
}

test "addze writes RT and leaves RA alone" {
    var buf: [16]u8 = @splat(0);
    var ctx = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    ctx.gpr[4] = 7;
    ctx.xer |= 1 << 2;
    try runWords(&ctx, &.{ 0x7c640194, 0x4e800020 }); // addze r3,r4
    try testing.expectEqual(@as(u64, 8), ctx.gpr[3]);
    try testing.expectEqual(@as(u64, 7), ctx.gpr[4]);
}

test "addic carry feeds subfe" {
    var buf: [16]u8 = @splat(0);
    var ctx = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    ctx.gpr[3] = 0xffffffffffffffff;
    ctx.gpr[4] = 0;
    ctx.gpr[5] = 1;
    try runWords(&ctx, &.{ 0x30630001, 0x7cc42910, 0x4e800020 }); // addic r3,r3,1; subfe r6,r4,r5
    try testing.expectEqual(@as(u64, 0), ctx.gpr[3]);
    try testing.expectEqual(@as(u64, 1), ctx.gpr[6]);
}

test "ds-form loads use byte offsets" {
    var buf: [64]u8 = @splat(0);
    var ctx = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    ctx.gpr[4] = 0x1000;
    ctx.store64(0x1008, 0x1122334455667788);
    // ld r6,8(r4)
    try runWords(&ctx, &.{ 0xE8C40008, 0x4e800020 });
    try testing.expectEqual(@as(u64, 0x1122334455667788), ctx.gpr[6]);
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
    try testing.expectError(error.Unsupported, run(&ctx, &.{0x44000002}));
}

test "record forms update CR0" {
    var buf: [16]u8 = @splat(0);

    var sub = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    sub.gpr[5] = 1;
    sub.gpr[6] = 1;
    try runWords(&sub, &.{ 0x7c662851, 0x4e800020 }); // subf. r3,r6,r5
    try testing.expectEqual(@as(u64, 0), sub.gpr[3]);
    try testing.expectEqual(@as(u1, 1), sub.crBit(2)); // equal

    var rot = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    rot.gpr[4] = 0x80000000;
    try runWords(&rot, &.{ 0x5483003f, 0x4e800020 }); // rlwinm. r3,r4,0,0,31
    try testing.expectEqual(@as(u64, 0x80000000), rot.gpr[3]);
    try testing.expectEqual(@as(u1, 1), rot.crBit(0)); // less than
}

test "bctr and bcctr run through ctr" {
    var buf: [16]u8 = @splat(0);

    const a = [_]u32{ 0x4e800420, 0x4e800020 }; // bctr; blr
    const bcctr_words = [_]u32{ 0x4d800420, 0x4e800020 }; // bcctr 12,0; blr
    const b = [_]u32{ 0x38600007, 0x4e800020 };
    const table = [_]Entry{
        .{ .addr = 0x1000, .words = &a },
        .{ .addr = 0x2000, .words = &b },
    };

    var direct = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    direct.ctr = 0x2000;
    try runTable(&direct, 0x1000, &a, &table);
    try testing.expectEqual(@as(u64, 7), direct.gpr[3]);

    var conditional = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    conditional.ctr = 0x2000;
    conditional.cr = 1 << 31;
    try runTable(&conditional, 0x1000, &bcctr_words, &table);
    try testing.expectEqual(@as(u64, 7), conditional.gpr[3]);
}

test "conditional bclr returns only when the condition is true" {
    var buf: [16]u8 = @splat(0);

    var taken = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    taken.cr = 1 << 29; // CR0 EQ
    try runWords(&taken, &.{ 0x4d820020, 0x38600001, 0x4e800020 });
    try testing.expectEqual(@as(u64, 0), taken.gpr[3]);

    var not_taken = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    try runWords(&not_taken, &.{ 0x4d820020, 0x38600001, 0x4e800020 });
    try testing.expectEqual(@as(u64, 1), not_taken.gpr[3]);
}

test "single-source float ops read frb" {
    var buf: [16]u8 = @splat(0);

    var fmr = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    fmr.fpr[1] = 2.5;
    try runWords(&fmr, &.{ 0xfc600890, 0x4e800020 }); // fmr f3,f1
    try testing.expectEqual(@as(f64, 2.5), fmr.fpr[3]);

    var frsp = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    frsp.fpr[1] = 3.5;
    try runWords(&frsp, &.{ 0xfc600818, 0x4e800020 }); // frsp f3,f1
    try testing.expectEqual(@as(f64, 3.5), frsp.fpr[3]);

    var fneg = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    fneg.fpr[1] = 3.5;
    try runWords(&fneg, &.{ 0xfc600850, 0x4e800020 }); // fneg f3,f1
    try testing.expectEqual(@as(f64, -3.5), fneg.fpr[3]);

    var fcfid = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    fcfid.fpr[1] = @bitCast(@as(u64, 5));
    try runWords(&fcfid, &.{ 0xfc600e9c, 0x4e800020 }); // fcfid f3,f1
    try testing.expectEqual(@as(f64, 5.0), fcfid.fpr[3]);
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

test "cmpw and cmpwi compare only the low 32 bits" {
    var buf: [16]u8 = @splat(0);

    var cmp = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    cmp.gpr[3] = 0x0000000080000000;
    cmp.gpr[4] = 0;
    try runWords(&cmp, &.{ 0x7c032000, 0x4e800020 }); // cmpw r3,r4
    try testing.expectEqual(@as(u1, 1), cmp.crBit(0)); // less than

    var cmp_imm = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    cmp_imm.gpr[3] = 0x0000000080000000;
    try runWords(&cmp_imm, &.{ 0x2c030000, 0x4e800020 }); // cmpwi r3,0
    try testing.expectEqual(@as(u1, 1), cmp_imm.crBit(0));
}

test "cmplw and cmplwi compare only the low 32 bits" {
    var buf: [16]u8 = @splat(0);

    var cmp = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    cmp.gpr[3] = 0xffffffff80000000;
    cmp.gpr[4] = 0x0000000080000000;
    try runWords(&cmp, &.{ 0x7c032040, 0x4e800020 }); // cmplw r3,r4
    try testing.expectEqual(@as(u1, 1), cmp.crBit(2)); // equal

    var cmp_imm = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    cmp_imm.gpr[3] = 0xffffffff00000000;
    try runWords(&cmp_imm, &.{ 0x28030000, 0x4e800020 }); // cmplwi r3,0
    try testing.expectEqual(@as(u1, 1), cmp_imm.crBit(2)); // equal
}

test "mulli keeps the high 32 bits of a 64-bit product" {
    var buf: [16]u8 = @splat(0);
    var ctx = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    ctx.gpr[3] = 0x0000000100000000;
    try runWords(&ctx, &.{ 0x1c633039, 0x4e800020 }); // mulli r3,r3,12345
    try testing.expectEqual(@as(u64, 0x0000303900000000), ctx.gpr[3]);
}

test "mullw keeps the low 32 bits" {
    var buf: [16]u8 = @splat(0);
    var ctx = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    ctx.gpr[3] = 0x0000000100000000;
    ctx.gpr[4] = 2;
    try runWords(&ctx, &.{ 0x7c6321d6, 0x4e800020 }); // mullw r3,r3,r4
    try testing.expectEqual(@as(u64, 0), ctx.gpr[3]);
}

test "fctiwz leaves integer bits for stfiwx" {
    var buf: [16]u8 = @splat(0);
    var ctx = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    ctx.gpr[4] = 0x1000;
    ctx.fpr[1] = 1.5;
    try runWords(&ctx, &.{ 0xfc60081e, 0x7c6027ae, 0x4e800020 }); // fctiwz f3,f1; stfiwx f3,0,r4
    try testing.expectEqual(@as(u64, 1), ctx.load32(0x1000));
}

test "fctiwz writes the invalid sentinel for nan" {
    var buf: [16]u8 = @splat(0);
    var ctx = ctx_mod.Ctx.init(.{ .base = 0x1000, .data = &buf });
    ctx.gpr[4] = 0x1000;
    ctx.fpr[1] = std.math.nan(f64);
    try runWords(&ctx, &.{ 0xfc60081e, 0x7c6027ae, 0x4e800020 });
    try testing.expectEqual(@as(u64, 0x80000000), ctx.load32(0x1000));
}
