//! Zig emitter for the P0 integer subset.
//!
//! Branches inside a function, float and VMX instructions are refused by name; the slice
//! selector must only choose functions this emitter accepts.

const std = @import("std");
const ppc = @import("../ppc/root.zig");
const abi = @import("abi.zig");

pub const Error = error{UnsupportedOpcode} || std.mem.Allocator.Error;

pub const Options = struct {
    addr: u32,
    /// Chunked projects call the central dispatch through `dispatch.zig`;
    /// a single-file slice defines `dispatch` in the same file.
    external_dispatch: bool = false,

    fn call(self: Options) []const u8 {
        return if (self.external_dispatch) "@import(\"dispatch.zig\").dispatch" else "dispatch";
    }
};

const insn = ppc.decode.Instruction;

/// Record forms are lowered only for the integer ops listed here. Other Rc
/// forms are refused until their CR update is implemented.
fn rcSupported(op: insn) bool {
    return switch (op) {
        .add, .subf, .mullw, .sraw, .srawi, .rlwinm, .rlwimi, .extsh, .extsb, .extsw, .cntlzw, .and_, .or_ => true,
        .stfiwx => |f| !f.rc,
        .stwx, .stbx, .lwzx, .lbzx => |f| !f.rc,
        .lfsx => |f| !f.rc,
        .rldicr => |f| !f.rc,
        .fadd, .fsub, .fmul, .fdiv, .fadds, .fsubs, .fmuls, .fdivs, .fctiwz, .frsp, .fneg, .fcfid, .fmr => |f| !f.rc,
        .fmadds => |f| !f.rc,
        else => true,
    };
}

pub fn supports(op: insn) bool {
    if (!rcSupported(op)) return false;
    return switch (op) {
        .padding,
        .addi,
        .addis,
        .ori,
        .oris,
        .andi_dot,
        .lwz,
        .lwzu,
        .stw,
        .stwu,
        .lbz,
        .lbzu,
        .sth,
        .blr,
        .stb,
        .cmpwi,
        .cmplwi,
        .or_,
        .add,
        .subf,
        .mullw,
        .sraw,
        .srawi,
        .rlwinm,
        .ld,
        .ldu,
        .lwa,
        .std,
        .stdu,
        .cmpw,
        .cmplw,
        .lwzx,
        .lbzx,
        .stwx,
        .mulli,
        .extsh,
        .extsb,
        .extsw,
        .cntlzw,
        .stbx,
        .lfsx,
        .lhz,
        .rlwimi,
        .frsp,
        .fneg,
        .fcfid,
        .xori,
        .subfic,
        .rldicr,
        .stfiwx,
        .and_,
        .lfd,
        .stfd,
        .fmr,
        .fadds,
        .fsubs,
        .fmuls,
        .fdivs,
        .fmadds,
        .fctiwz,
        .lfs,
        .stfs,
        .lvx,
        .stvx,
        .lvewx,
        .lvehx,
        .lvsl,
        .lvsr,
        .vmx,
        .vor,
        .vxor,
        .vaddfp,
        .vcmpequb,
        .vcmpgtub,
        .vand,
        .vsubfp,
        .vrlw,
        .vperm,
        .vmaddfp,
        .vspltisw,
        .fadd,
        .fsub,
        .fmul,
        .fdiv,
        .fcmpu,
        .mflr,
        .mtlr,
        .mfctr,
        .mtctr,
        .nop,
        .addic,
        .twi,
        .tw,
        .andis_dot,
        .cr_op,
        .mcrf,
        .rfid,
        .fsqrts,
        .fsqrt,
        .fsel,
        .fctid,
        .fctidz,
        .fmsubs,
        .fnmsubs,
        .fnmadds,
        .fmadd,
        .fmsub,
        .fnmsub,
        .fnmadd,
        .fabs,
        .fnabs,
        .mffs,
        .mtfsf,
        .lfsu,
        .lfsux,
        .stfsu,
        .lfdu,
        .stfdu,
        .lfdx,
        .lfdux,
        .stfsx,
        .stfdx,
        .xoris,
        .addc,
        .adde,
        .addze,
        .addme,
        .subfc,
        .subfe,
        .subfme,
        .subfze,
        .neg,
        .mulhw,
        .mulhwu,
        .mulld,
        .mulhd,
        .mulhdu,
        .divw,
        .divwu,
        .divd,
        .divdu,
        .rlwnm,
        .stbux,
        .slw,
        .srw,
        .sld,
        .srd,
        .srad,
        .sradi,
        .xor_,
        .andc,
        .eqv,
        .nor_,
        .nand,
        .orc,
        .cntlzd,
        .cmpd,
        .cmpld,
        .mfspr,
        .mtspr,
        .mftb,
        .mfmsr,
        .mtmsr,
        .mtmsrd,
        .mtocrf,
        .mfocrf,
        .lwsync,
        .sync,
        .isync,
        .eieio,
        .dcbt,
        .dcbtst,
        .dcbf,
        .dcbst,
        .dcbz,
        .icbi,
        .tlbiel,
        .tlbie,
        .slbmte,
        .slbia,
        .lwarx,
        .ldarx,
        .stwcx,
        .stdcx,
        .lhzu,
        .lhzux,
        .lha,
        .lhau,
        .stbu,
        .sthu,
        .sthx,
        .ldx,
        .stdx,
        .lwzux,
        .lwax,
        .stwux,
        .sthux,
        .stdux,
        .lbzux,
        .lwbrx,
        .lhbrx,
        .lhax,
        .lhaux,
        .stwbrx,
        .sthbrx,
        => true,
        else => false,
    };
}

/// `supports`, plus the checks that need the instruction's position: branches must stay
/// inside the function and use a supported form.
pub fn supportsAt(op: insn, at: u32, base: u32, end: u32) bool {
    _ = at;
    _ = base;
    _ = end;
    return switch (op) {
        .b, .bc, .bclr, .bl => true,
        else => supports(op),
    };
}

pub fn supportsAll(base: u32, words: []const u32) bool {
    const end = base +% @as(u32, @intCast(words.len)) * 4;
    for (words, 0..) |word, i| {
        const at = base + @as(u32, @intCast(i)) * 4;
        const op = ppc.decode.decode(word) catch return false;
        if (!supportsAt(op, at, base, end)) return false;
    }
    return true;
}

fn inRange(target: u32, base: u32, end: u32) bool {
    return target >= base and target < end and (target - base) % 4 == 0;
}

pub fn function(allocator: std.mem.Allocator, words: []const u32, opts: Options) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    const base = opts.addr;
    const end = base +% @as(u32, @intCast(words.len)) * 4;

    var has_branch = false;
    for (words, 0..) |word, i| {
        const at = base + @as(u32, @intCast(i)) * 4;
        const op = ppc.decode.decode(word) catch return error.UnsupportedOpcode;
        switch (op) {
            .b, .bc, .bclr, .rfid => has_branch = true,
            else => {},
        }
        if (!supportsAt(op, at, base, end)) return error.UnsupportedOpcode;
    }

    var name_buf: [10]u8 = undefined;
    try out.print(allocator, "pub fn {s}(ctx: *Ctx) callconv(.c) void {{\n", .{
        abi.fnName(opts.addr, &name_buf),
    });
    try out.print(allocator, "    if (ctx.depth >= Ctx.max_call_depth) {{\n        ctx.fault = .{{ .kind = .recursion, .addr = 0x{X} }};\n        return;\n    }}\n    ctx.depth += 1;\n    defer ctx.depth -= 1;\n", .{opts.addr});

    if (!has_branch) {
        for (words, 0..) |word, i| {
            const addr = base + @as(u32, @intCast(i)) * 4;
            try out.print(allocator, "    // 0x{X:0>8}\n", .{addr});
            try out.appendSlice(allocator, "    if (ctx.budget != 0) {\n        ctx.budget -= 1;\n        if (ctx.budget == 0) return;\n    }\n");
            const op = ppc.decode.decode(word) catch return error.UnsupportedOpcode;
            if (op == .blr) {
                try out.appendSlice(allocator, "    return;\n");
                break;
            }
            try lower(allocator, &out, op, addr, opts.call());
        }
        try out.appendSlice(allocator, "}\n");
        return out.toOwnedSlice(allocator);
    }

    try out.print(allocator, "    var pc: u32 = 0x{X};\n", .{base});
    try out.appendSlice(allocator, "    _ = &pc;\n");
    try out.appendSlice(allocator, "    while (true) {\n");
    try out.appendSlice(allocator, "        if (ctx.budget != 0) {\n            ctx.budget -= 1;\n            if (ctx.budget == 0) return;\n        }\n");
    try out.appendSlice(allocator, "        switch (pc) {\n");

    for (words, 0..) |word, i| {
        const addr = base + @as(u32, @intCast(i)) * 4;
        const next = addr + 4;

        try out.print(allocator, "            0x{X} => {{\n", .{addr});
        const op = ppc.decode.decode(word) catch return error.UnsupportedOpcode;

        switch (op) {
            .blr => try out.appendSlice(allocator, "                return;\n"),
            .b => |f| {
                const target = if (f.absolute) f.target else addr +% f.target;
                if (inRange(target, base, end)) {
                    try out.print(allocator, "                pc = 0x{X};\n", .{target});
                } else {
                    try tailCall(allocator, &out, target, opts.call());
                }
            },
            .bc => |f| {
                const target = if (f.absolute) f.target else addr +% f.target;
                if (f.link and target == next) {
                    try out.print(allocator, "                ctx.lr = 0x{X};\n                pc = 0x{X};\n", .{ next, next });
                } else if (f.link) {
                    try out.print(allocator, "                if (ctx.branch({d}, {d})) {{\n", .{ f.bo, f.bi });
                    try out.print(allocator, "                    ctx.lr = 0x{X};\n", .{next});
                    try out.print(allocator, "                    if (!{s}(0x{X}, ctx)) {{\n                        ctx.fault = .{{ .kind = .unsupported, .addr = 0x{X} }};\n                        return;\n                    }}\n", .{ opts.call(), target, target });
                    try out.print(allocator, "                }}\n                pc = 0x{X};\n", .{next});
                } else if (inRange(target, base, end)) {
                    try out.print(allocator, "                pc = if (ctx.branch({d}, {d})) 0x{X} else 0x{X};\n", .{
                        f.bo, f.bi, target, next,
                    });
                } else {
                    try out.print(allocator, "                if (ctx.branch({d}, {d})) {{\n", .{ f.bo, f.bi });
                    try tailCall(allocator, &out, target, opts.call());
                    try out.print(allocator, "                }}\n                pc = 0x{X};\n", .{next});
                }
            },
            .bclr => |f| {
                const target = if (f.to_ctr) "ctx.ctr" else "ctx.lr";
                if (f.link) {
                    try out.print(allocator, "                if (ctx.branch({d}, {d})) {{\n", .{ f.bo, f.bi });
                    try out.print(allocator, "                    const target: u32 = {s};\n", .{target});
                    try out.print(allocator, "                    ctx.lr = 0x{X};\n", .{next});
                    try out.print(allocator, "                    if (!{s}(target, ctx)) {{\n                        ctx.fault = .{{ .kind = .unsupported, .addr = target }};\n                        return;\n                    }}\n", .{opts.call()});
                    try out.print(allocator, "                }}\n                pc = 0x{X};\n", .{next});
                } else if (f.to_ctr) {
                    try out.print(allocator, "                if (ctx.branch({d}, {d})) {{\n", .{ f.bo, f.bi });
                    try out.print(allocator, "                    if (!{s}(ctx.ctr, ctx)) {{\n                        ctx.fault = .{{ .kind = .unsupported, .addr = ctx.ctr }};\n                    }}\n", .{opts.call()});
                    try out.print(allocator, "                    return;\n                }}\n                pc = 0x{X};\n", .{next});
                } else {
                    try out.print(allocator, "                if (ctx.branch({d}, {d})) return;\n                pc = 0x{X};\n", .{
                        f.bo, f.bi, next,
                    });
                }
            },
            .rfid => try out.appendSlice(allocator, "                ctx.msr = ctx.getSpr(27);\n                pc = @truncate(ctx.getSpr(26));\n"),
            else => {
                try lower(allocator, &out, op, addr, opts.call());
                try out.print(allocator, "                pc = 0x{X};\n", .{next});
            },
        }
        try out.appendSlice(allocator, "            },\n");
    }

    try out.appendSlice(allocator, "            else => return,\n        }\n    }\n}\n");
    return out.toOwnedSlice(allocator);
}

fn tailCall(allocator: std.mem.Allocator, out: *std.ArrayList(u8), target: u32, call: []const u8) !void {
    try out.print(allocator, "                if (!{s}(0x{X}, ctx)) {{\n                    ctx.fault = .{{ .kind = .unsupported, .addr = 0x{X} }};\n                }}\n                return;\n", .{ call, target, target });
}

fn lower(allocator: std.mem.Allocator, out: *std.ArrayList(u8), op: insn, addr: u32, call: []const u8) Error!void {
    switch (op) {
        .bl => |f| {
            const target = if (f.absolute) f.target else addr +% f.target;
            try out.print(allocator, "    ctx.lr = 0x{X};\n    if (!{s}(0x{X}, ctx)) {{\n        ctx.fault = .{{ .kind = .unsupported, .addr = 0x{X} }};\n        return;\n    }}\n", .{
                addr +% 4, call, target, target,
            });
        },
        .nop, .padding => {},
        .addi => try immAdd(allocator, out, op.addi.rt, op.addi.ra, sext(op.addi.imm)),
        .addis => try immAdd(allocator, out, op.addis.rt, op.addis.ra, sext32(op.addis.imm)),
        .ori => try immU32(allocator, out, "|", op.ori.ra, op.ori.rt, op.ori.imm),
        .oris => try immU32Shifted(allocator, out, op.oris.ra, op.oris.rt, op.oris.imm),
        .andi_dot => {
            try immU32(allocator, out, "&", op.andi_dot.ra, op.andi_dot.rt, op.andi_dot.imm);
            try out.print(allocator, "    ctx.setCr(0, ctx.gpr[{d}], 0, true);\n", .{op.andi_dot.ra});
        },
        .or_ => {
            try binop(allocator, out, "|", op.or_.ra, op.or_.rt, op.or_.rb);
            try recordCr(allocator, out, op.or_.rc, false, op.or_.ra);
        },
        .add => {
            try binop(allocator, out, "+%", op.add.rt, op.add.ra, op.add.rb);
            try recordCr(allocator, out, op.add.rc, false, op.add.rt);
        },
        .subf => {
            try subf(allocator, out, op.subf.rt, op.subf.ra, op.subf.rb);
            try recordCr(allocator, out, op.subf.rc, false, op.subf.rt);
        },
        .mullw => {
            try out.print(allocator, "    ctx.gpr[{d}] = @as(u32, @truncate(ctx.gpr[{d}] *% ctx.gpr[{d}]));\n", .{ op.mullw.rt, op.mullw.ra, op.mullw.rb });
            try recordCr(allocator, out, op.mullw.rc, true, op.mullw.rt);
        },
        .sraw => {
            try out.print(allocator, "    ctx.gpr[{d}] = ctx.sraw32(ctx.gpr[{d}], ctx.gpr[{d}]);\n", .{ op.sraw.ra, op.sraw.rt, op.sraw.rb });
            try recordCr(allocator, out, op.sraw.rc, true, op.sraw.ra);
        },
        .srawi => {
            try out.print(allocator, "    ctx.gpr[{d}] = ctx.sraw32(ctx.gpr[{d}], {d});\n", .{
                op.srawi.ra, op.srawi.rs, op.srawi.sh,
            });
            try recordCr(allocator, out, op.srawi.rc, true, op.srawi.ra);
        },
        .rlwinm => {
            try out.print(allocator, "    ctx.gpr[{d}] = @as(u32, std.math.rotl(u32, @as(u32, @truncate(ctx.gpr[{d}])), {d})) & 0x{X:0>8};\n", .{
                op.rlwinm.ra, op.rlwinm.rs, op.rlwinm.sh, mask32(op.rlwinm.mb, op.rlwinm.me),
            });
            try recordCr(allocator, out, op.rlwinm.rc, true, op.rlwinm.ra);
        },
        .rlwnm => {
            try out.print(allocator, "    ctx.gpr[{d}] = std.math.rotl(u32, @as(u32, @truncate(ctx.gpr[{d}])), @as(u5, @truncate(ctx.gpr[{d}]))) & 0x{X:0>8};\n", .{
                op.rlwnm.ra, op.rlwnm.rs, op.rlwnm.rb, mask32(op.rlwnm.mb, op.rlwnm.me),
            });
            try recordCr(allocator, out, op.rlwnm.rc, true, op.rlwnm.ra);
        },
        .mflr => try mov(allocator, out, op.mflr.rt, "lr"),
        .mtlr => try movTo(allocator, out, "lr", op.mtlr.rt),
        .mfctr => try mov(allocator, out, op.mfctr.rt, "ctr"),
        .mtctr => try movTo(allocator, out, "ctr", op.mtctr.rt),
        .lwz => try load(allocator, out, op, 4, false),
        .lwzu => try load(allocator, out, op, 4, true),
        .lbz => try load(allocator, out, op, 1, false),
        .lbzu => try load(allocator, out, op, 1, true),
        .sth => {
            if (op.sth.ra == 0) {
                try out.print(allocator, "    ctx.store16(0 +% 0x{X:0>8}, ctx.gpr[{d}]);\n", .{ @as(u32, @bitCast(@as(i32, op.sth.imm))), op.sth.rt });
            } else {
                try out.print(allocator, "    ctx.store16(@as(u32, @truncate(ctx.gpr[{d}])) +% 0x{X:0>8}, ctx.gpr[{d}]);\n", .{ op.sth.ra, @as(u32, @bitCast(@as(i32, op.sth.imm))), op.sth.rt });
            }
        },
        .stw, .stb => try store(allocator, out, op, false),
        .stwu => try store(allocator, out, op, true),
        .lfd => {
            if (op.lfd.ra == 0) {
                try out.print(allocator, "    ctx.fpr[{d}] = @bitCast(ctx.load64(0 +% 0x{X:0>16}));\n", .{ op.lfd.frd, @as(u32, @bitCast(@as(i32, op.lfd.imm))) });
            } else {
                try out.print(allocator, "    ctx.fpr[{d}] = @bitCast(ctx.load64(@as(u32, @truncate(ctx.gpr[{d}])) +% 0x{X:0>16}));\n", .{ op.lfd.frd, op.lfd.ra, @as(u32, @bitCast(@as(i32, op.lfd.imm))) });
            }
        },
        .stfd => {
            if (op.stfd.ra == 0) {
                try out.print(allocator, "    ctx.store64(0 +% 0x{X:0>16}, @bitCast(ctx.fpr[{d}]));\n", .{ @as(u32, @bitCast(@as(i32, op.stfd.imm))), op.stfd.frd });
            } else {
                try out.print(allocator, "    ctx.store64(@as(u32, @truncate(ctx.gpr[{d}])) +% 0x{X:0>16}, @bitCast(ctx.fpr[{d}]));\n", .{ op.stfd.ra, @as(u32, @bitCast(@as(i32, op.stfd.imm))), op.stfd.frd });
            }
        },
        .fmr => try out.print(allocator, "    ctx.fpr[{d}] = ctx.fpr[{d}];\n", .{ op.fmr.frd, op.fmr.frb }),
        .fadds => try out.print(allocator, "    ctx.fpr[{d}] = @floatCast(@as(f32, @floatCast(ctx.fpr[{d}])) + @as(f32, @floatCast(ctx.fpr[{d}])));\n", .{ op.fadds.frd, op.fadds.fra, op.fadds.frb }),
        .fsubs => try out.print(allocator, "    ctx.fpr[{d}] = @floatCast(@as(f32, @floatCast(ctx.fpr[{d}])) - @as(f32, @floatCast(ctx.fpr[{d}])));\n", .{ op.fsubs.frd, op.fsubs.fra, op.fsubs.frb }),
        .fmuls => try out.print(allocator, "    ctx.fpr[{d}] = @floatCast(@as(f32, @floatCast(ctx.fpr[{d}])) * @as(f32, @floatCast(ctx.fpr[{d}])));\n", .{ op.fmuls.frd, op.fmuls.fra, op.fmuls.frb }),
        .fdivs => try out.print(allocator, "    ctx.fpr[{d}] = @floatCast(@as(f32, @floatCast(ctx.fpr[{d}])) / @as(f32, @floatCast(ctx.fpr[{d}])));\n", .{ op.fdivs.frd, op.fdivs.fra, op.fdivs.frb }),
        .fmadds => try out.print(allocator, "    ctx.fpr[{d}] = @floatCast(@as(f32, @floatCast(ctx.fpr[{d}])) * @as(f32, @floatCast(ctx.fpr[{d}])) + @as(f32, @floatCast(ctx.fpr[{d}])));\n", .{ op.fmadds.frd, op.fmadds.fra, op.fmadds.frc, op.fmadds.frb }),
        .fctiwz => try out.print(allocator, "    ctx.fpr[{d}] = ctx.fctiwz(ctx.fpr[{d}]);\n", .{ op.fctiwz.frd, op.fctiwz.frb }),
        .lfs => try fLoad(allocator, out, op.lfs.frd, op.lfs.ra, op.lfs.imm),
        .lfsu => try fLoadUpdate(allocator, out, op.lfsu.frd, op.lfsu.ra, op.lfsu.imm, 32),
        .stfsu => try fStoreUpdate(allocator, out, op.stfsu.frd, op.stfsu.ra, op.stfsu.imm, 32),
        .lfdu => try fLoadUpdate(allocator, out, op.lfdu.frd, op.lfdu.ra, op.lfdu.imm, 64),
        .stfdu => try fStoreUpdate(allocator, out, op.stfdu.frd, op.stfdu.ra, op.stfdu.imm, 64),
        .lfdx => try fIndexedLoad(allocator, out, op.lfdx.frd, op.lfdx.fra, op.lfdx.frb, 64),
        .lfdux => try fIndexedUpdateLoad64(allocator, out, op.lfdux.frd, op.lfdux.fra, op.lfdux.frb),
        .stfsx => try fIndexedStore(allocator, out, op.stfsx.frd, op.stfsx.fra, op.stfsx.frb, 32),
        .stfdx => try fIndexedStore(allocator, out, op.stfdx.frd, op.stfdx.fra, op.stfdx.frb, 64),
        .lvx => try vmem(allocator, out, op.lvx, true),
        .stvx => try vmem(allocator, out, op.stvx, false),
        .vor, .vxor, .vaddfp, .vand, .vsubfp, .vrlw, .vcmpequb, .vcmpgtub => {
            const f = switch (op) {
                .vor => |v| v,
                .vxor => |v| v,
                .vaddfp => |v| v,
                .vand => |v| v,
                .vsubfp => |v| v,
                .vrlw => |v| v,
                .vcmpequb => |v| v,
                .vcmpgtub => |v| v,
                else => return error.UnsupportedOpcode,
            };
            const name = @tagName(std.meta.activeTag(op));
            try out.print(allocator, "    ctx.vmx[{d}] = ctx.{s}(ctx.vmx[{d}], ctx.vmx[{d}]);\n", .{ f.vd, name, f.va, f.vb });
        },
        .vperm => try out.print(allocator, "    ctx.vmx[{d}] = ctx.vperm(ctx.vmx[{d}], ctx.vmx[{d}], ctx.vmx[{d}]);\n", .{ op.vperm.vd, op.vperm.va, op.vperm.vb, op.vperm.vc }),
        .vmaddfp => try out.print(allocator, "    ctx.vmx[{d}] = ctx.vmaddfp(ctx.vmx[{d}], ctx.vmx[{d}], ctx.vmx[{d}]);\n", .{ op.vmaddfp.vd, op.vmaddfp.va, op.vmaddfp.vc, op.vmaddfp.vb }),
        .vspltisw => try out.print(allocator, "    ctx.vmx[{d}] = ctx.vspltisw({d});\n", .{ op.vspltisw.vd, op.vspltisw.simm }),
        .lvewx => try out.print(allocator, "    ctx.vmx[{d}] = ctx.lvewx(@as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}])));\n", .{ op.lvewx.vd, op.lvewx.ra, op.lvewx.rb }),
        .lvehx => try out.print(allocator, "    ctx.vmx[{d}] = ctx.lvehx(@as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}])));\n", .{ op.lvehx.vd, op.lvehx.ra, op.lvehx.rb }),
        .vmx => |f| {
            const kind = @tagName(f.kind);
            switch (f.kind) {
                .vcmpequq, .vcmpequd, .vcmpeqfp, .vcmpneb, .vucmprlb, .vcmpnezb, .vcmpneh, .vcmpnezh, .vcmpnezw => {
                    try out.print(allocator, "    ctx.vmx[{d}] = ctx.vmxCmp({d}, ctx.vmx[{d}], ctx.vmx[{d}]);\n", .{ f.vd, @backingInt(f.kind), f.va, f.vb });
                },
                .vadduwm, .vdivud, .vslb => {
                    try out.print(allocator, "    ctx.vmx[{d}] = ctx.{s}(ctx.vmx[{d}], ctx.vmx[{d}]);\n", .{ f.vd, kind, f.va, f.vb });
                },
                .vsel => {
                    try out.print(allocator, "    ctx.vmx[{d}] = ctx.vsel(ctx.vmx[{d}], ctx.vmx[{d}], ctx.vmx[{d}]);\n", .{ f.vd, f.va, f.vb, f.vc });
                },
                .vsldoi => {
                    try out.print(allocator, "    ctx.vmx[{d}] = ctx.vsldoi(ctx.vmx[{d}], ctx.vmx[{d}], {d});\n", .{ f.vd, f.va, f.vb, f.imm & 0xf });
                },
                .vnmsubfp => {
                    try out.print(allocator, "    ctx.vmx[{d}] = ctx.vnmsubfp(ctx.vmx[{d}], ctx.vmx[{d}], ctx.vmx[{d}]);\n", .{ f.vd, f.va, f.vb, f.vc });
                },
            }
        },
        .stfs => try fStore(allocator, out, op.stfs.frd, op.stfs.ra, op.stfs.imm),
        .fmsubs => try fma(allocator, out, "f32", "-", op.fmsubs.frd, op.fmsubs.fra, op.fmsubs.frc, op.fmsubs.frb, false),
        .fnmsubs => try fma(allocator, out, "f32", "-", op.fnmsubs.frd, op.fnmsubs.fra, op.fnmsubs.frc, op.fnmsubs.frb, true),
        .fnmadds => try fma(allocator, out, "f32", "+", op.fnmadds.frd, op.fnmadds.fra, op.fnmadds.frc, op.fnmadds.frb, true),
        .fmadd => try fma(allocator, out, "f64", "+", op.fmadd.frd, op.fmadd.fra, op.fmadd.frc, op.fmadd.frb, false),
        .fmsub => try fma(allocator, out, "f64", "-", op.fmsub.frd, op.fmsub.fra, op.fmsub.frc, op.fmsub.frb, false),
        .fnmsub => try fma(allocator, out, "f64", "-", op.fnmsub.frd, op.fnmsub.fra, op.fnmsub.frc, op.fnmsub.frb, true),
        .fnmadd => try fma(allocator, out, "f64", "+", op.fnmadd.frd, op.fnmadd.fra, op.fnmadd.frc, op.fnmadd.frb, true),
        .fabs => try out.print(allocator, "    ctx.fpr[{d}] = @abs(ctx.fpr[{d}]);\n", .{ op.fabs.frd, op.fabs.frb }),
        .fnabs => try out.print(allocator, "    ctx.fpr[{d}] = -@abs(ctx.fpr[{d}]);\n", .{ op.fnabs.frd, op.fnabs.frb }),
        .mffs => try out.print(allocator, "    ctx.fpr[{d}] = @bitCast(@as(u64, ctx.fpscr));\n", .{op.mffs.frd}),
        .mtfsf => try out.print(allocator, "    ctx.fpscr = @truncate(@as(u64, @bitCast(ctx.fpr[{d}])));\n", .{op.mtfsf.frb}),
        .fsqrt => try out.print(allocator, "    ctx.fpr[{d}] = @sqrt(ctx.fpr[{d}]);\n", .{ op.fsqrt.frd, op.fsqrt.frb }),
        .fsel => try out.print(allocator, "    ctx.fpr[{d}] = ctx.fsel(ctx.fpr[{d}], ctx.fpr[{d}], ctx.fpr[{d}]);\n", .{ op.fsel.frd, op.fsel.fra, op.fsel.frb, op.fsel.frc }),
        .fctid => try out.print(allocator, "    ctx.fpr[{d}] = ctx.fctidz(ctx.fpr[{d}]);\n", .{ op.fctid.frd, op.fctid.frb }),
        .fsqrts => try out.print(allocator, "    ctx.fpr[{d}] = @floatCast(@sqrt(@as(f32, @floatCast(ctx.fpr[{d}]))));\n", .{ op.fsqrts.frd, op.fsqrts.frb }),
        .fctidz => try out.print(allocator, "    ctx.fpr[{d}] = ctx.fctidz(ctx.fpr[{d}]);\n", .{ op.fctidz.frd, op.fctidz.frb }),
        .fadd => try fBinop(allocator, out, "+", op.fadd.frd, op.fadd.fra, op.fadd.frb),
        .fsub => try fBinop(allocator, out, "-", op.fsub.frd, op.fsub.fra, op.fsub.frb),
        .fmul => try fBinop(allocator, out, "*", op.fmul.frd, op.fmul.fra, op.fmul.frb),
        .fdiv => try fBinop(allocator, out, "/", op.fdiv.frd, op.fdiv.fra, op.fdiv.frb),
        .fcmpu => try out.print(allocator, "    ctx.setCrFloat({d}, ctx.fpr[{d}], ctx.fpr[{d}]);\n", .{
            op.fcmpu.crf, op.fcmpu.fra, op.fcmpu.frb,
        }),
        .ld => try load64(allocator, out, op.ld.rt, op.ld.ra, op.ld.ds, false),
        .ldu => try load64(allocator, out, op.ldu.rt, op.ldu.ra, op.ldu.ds, true),
        .lwa => {
            if (op.lwa.ra == 0) {
                try out.print(allocator, "    ctx.gpr[{d}] = @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(ctx.load32(0 +% 0x{X:0>8})))))));\n", .{ op.lwa.rt, @as(u32, @bitCast(@as(i32, op.lwa.ds))) });
            } else {
                try out.print(allocator, "    ctx.gpr[{d}] = @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(ctx.load32(@as(u32, @truncate(ctx.gpr[{d}])) +% 0x{X:0>8})))))));\n", .{ op.lwa.rt, op.lwa.ra, @as(u32, @bitCast(@as(i32, op.lwa.ds))) });
            }
        },
        .cmpw => try out.print(allocator, "    ctx.setCr32({d}, ctx.gpr[{d}], ctx.gpr[{d}], true);\n", .{ op.cmpw.crf, op.cmpw.ra, op.cmpw.rb }),
        .cmplw => try out.print(allocator, "    ctx.setCr32({d}, ctx.gpr[{d}], ctx.gpr[{d}], false);\n", .{ op.cmplw.crf, op.cmplw.ra, op.cmplw.rb }),
        .lwzx => try indexedLoad(allocator, out, op.lwzx.rt, op.lwzx.ra, op.lwzx.rb, 4),
        .lbzx => try indexedLoad(allocator, out, op.lbzx.rt, op.lbzx.ra, op.lbzx.rb, 1),
        .stwx => try indexedStore(allocator, out, op.stwx.rt, op.stwx.ra, op.stwx.rb, 32),
        .mulli => try out.print(allocator, "    ctx.gpr[{d}] = @bitCast(@as(i64, @bitCast(ctx.gpr[{d}])) *% @as(i64, {d}));\n", .{ op.mulli.rt, op.mulli.ra, op.mulli.imm }),
        .extsh => {
            try out.print(allocator, "    ctx.gpr[{d}] = @as(u64, @bitCast(@as(i64, @as(i16, @bitCast(@as(u16, @truncate(ctx.gpr[{d}])))))));\n", .{ op.extsh.ra, op.extsh.rt });
            try recordCr(allocator, out, op.extsh.rc, true, op.extsh.ra);
        },
        .extsb => {
            try out.print(allocator, "    ctx.gpr[{d}] = @as(u64, @bitCast(@as(i64, @as(i8, @bitCast(@as(u8, @truncate(ctx.gpr[{d}])))))));\n", .{ op.extsb.ra, op.extsb.rt });
            try recordCr(allocator, out, op.extsb.rc, true, op.extsb.ra);
        },
        .extsw => {
            try out.print(allocator, "    ctx.gpr[{d}] = @as(u64, @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(ctx.gpr[{d}])))))));\n", .{ op.extsw.ra, op.extsw.rt });
            try recordCr(allocator, out, op.extsw.rc, true, op.extsw.ra);
        },
        .std => try store64(allocator, out, op.std.rt, op.std.ra, op.std.ds, false),
        .stdu => try store64(allocator, out, op.stdu.rt, op.stdu.ra, op.stdu.ds, true),
        .cntlzw => {
            try out.print(allocator, "    ctx.gpr[{d}] = @clz(@as(u32, @truncate(ctx.gpr[{d}])));\n", .{ op.cntlzw.ra, op.cntlzw.rt });
            try recordCr(allocator, out, op.cntlzw.rc, true, op.cntlzw.ra);
        },
        .stbx => try indexedStore(allocator, out, op.stbx.rt, op.stbx.ra, op.stbx.rb, 8),
        .lfsx => {
            if (op.lfsx.fra == 0) {
                try out.print(allocator, "    ctx.fpr[{d}] = @floatCast(@as(f32, @bitCast(@as(u32, @truncate(ctx.load32(@as(u32, @truncate(ctx.gpr[{d}]))))))));\n", .{ op.lfsx.frd, op.lfsx.frb });
            } else {
                try out.print(allocator, "    ctx.fpr[{d}] = @floatCast(@as(f32, @bitCast(@as(u32, @truncate(ctx.load32(@as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}]))))))));\n", .{ op.lfsx.frd, op.lfsx.fra, op.lfsx.frb });
            }
        },
        .lhz => {
            if (op.lhz.ra == 0) {
                try out.print(allocator, "    ctx.gpr[{d}] = ctx.load16(0 +% 0x{X:0>8});\n", .{ op.lhz.rt, @as(u32, @bitCast(@as(i32, op.lhz.imm))) });
            } else {
                try out.print(allocator, "    ctx.gpr[{d}] = ctx.load16(@as(u32, @truncate(ctx.gpr[{d}])) +% 0x{X:0>8});\n", .{ op.lhz.rt, op.lhz.ra, @as(u32, @bitCast(@as(i32, op.lhz.imm))) });
            }
        },
        .rlwimi => {
            try out.print(allocator, "    ctx.gpr[{d}] = (ctx.gpr[{d}] & ~@as(u32, 0x{X:0>8})) | (@as(u32, std.math.rotl(u32, @as(u32, @truncate(ctx.gpr[{d}])), {d})) & 0x{X:0>8});\n", .{
                op.rlwimi.ra, op.rlwimi.ra, mask32(op.rlwimi.mb, op.rlwimi.me), op.rlwimi.rs, op.rlwimi.sh, mask32(op.rlwimi.mb, op.rlwimi.me),
            });
            try recordCr(allocator, out, op.rlwimi.rc, true, op.rlwimi.ra);
        },
        .frsp => try out.print(allocator, "    ctx.fpr[{d}] = @floatCast(@as(f32, @floatCast(ctx.fpr[{d}])));\n", .{ op.frsp.frd, op.frsp.frb }),
        .fneg => try out.print(allocator, "    ctx.fpr[{d}] = -ctx.fpr[{d}];\n", .{ op.fneg.frd, op.fneg.frb }),
        .fcfid => try out.print(allocator, "    ctx.fpr[{d}] = @floatFromInt(@as(i64, @bitCast(ctx.fpr[{d}])));\n", .{ op.fcfid.frd, op.fcfid.frb }),
        .xori => try immU32(allocator, out, "^", op.xori.ra, op.xori.rt, op.xori.imm),
        .subfic => try out.print(allocator, "    ctx.gpr[{d}] = 0x{X:0>16} -% ctx.gpr[{d}];\n", .{ op.subfic.ra, @as(u64, @bitCast(@as(i64, op.subfic.imm))), op.subfic.rt }),
        .rldicr => try out.print(allocator, "    ctx.gpr[{d}] = std.math.rotl(u64, ctx.gpr[{d}], {d}) & 0x{X:0>16};\n", .{
            op.rldicr.ra, op.rldicr.rs, op.rldicr.sh, rldicrMask(op.rldicr.me),
        }),
        .stfiwx => {
            if (op.stfiwx.ra == 0) {
                try out.print(allocator, "    ctx.store32(0 +% @as(u32, @truncate(ctx.gpr[{d}])), @as(u32, @truncate(@as(u64, @bitCast(ctx.fpr[{d}])))));\n", .{ op.stfiwx.rb, op.stfiwx.rt });
            } else {
                try out.print(allocator, "    ctx.store32(@as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}])), @as(u32, @truncate(@as(u64, @bitCast(ctx.fpr[{d}])))));\n", .{ op.stfiwx.ra, op.stfiwx.rb, op.stfiwx.rt });
            }
        },
        .and_ => try binop(allocator, out, "&", op.and_.ra, op.and_.rt, op.and_.rb),
        .cmpwi => try compareImm(allocator, out, op.cmpwi.crf, op.cmpwi.ra, op.cmpwi.imm, true),
        .cmplwi => try compareImm(allocator, out, op.cmplwi.crf, op.cmplwi.ra, op.cmplwi.imm, false),
        .addic => {
            if (op.addic.ra == 0) {
                try out.print(allocator, "    ctx.gpr[{d}] = ctx.addic(0, {d});\n", .{ op.addic.rt, op.addic.imm });
            } else {
                try out.print(allocator, "    ctx.gpr[{d}] = ctx.addic(ctx.gpr[{d}], {d});\n", .{ op.addic.rt, op.addic.ra, op.addic.imm });
            }
            try recordCr(allocator, out, op.addic.rc, false, op.addic.rt);
        },
        .addc, .adde, .subfc, .subfe, .subfme, .subfze, .addze, .addme, .neg => {
            const rt, const ra, const rb, const rc, const name = switch (op) {
                .addc => |f| .{ f.rt, f.ra, f.rb, f.rc, "addc" },
                .adde => |f| .{ f.rt, f.ra, f.rb, f.rc, "adde" },
                .subfc => |f| .{ f.rt, f.ra, f.rb, f.rc, "subfc" },
                .subfe => |f| .{ f.rt, f.ra, f.rb, f.rc, "subfe" },
                .subfme => |f| .{ f.rt, f.ra, f.rb, f.rc, "subfme" },
                .subfze => |f| .{ f.rt, f.ra, f.rb, f.rc, "subfze" },
                .addze => |f| .{ f.rt, f.ra, f.rb, f.rc, "addze" },
                .addme => |f| .{ f.rt, f.ra, f.rb, f.rc, "addme" },
                .neg => |f| .{ f.rt, f.ra, f.rb, f.rc, "neg" },
                else => return error.UnsupportedOpcode,
            };
            if (std.mem.eql(u8, name, "addze") or std.mem.eql(u8, name, "addme") or std.mem.eql(u8, name, "neg")) {
                try out.print(allocator, "    ctx.gpr[{d}] = ctx.{s}(ctx.gpr[{d}]);\n", .{ rt, name, ra });
            } else if (std.mem.eql(u8, name, "subfme") or std.mem.eql(u8, name, "subfze")) {
                try out.print(allocator, "    ctx.gpr[{d}] = ctx.{s}(ctx.gpr[{d}]);\n", .{ rt, name, ra });
            } else {
                try out.print(allocator, "    ctx.gpr[{d}] = ctx.{s}(ctx.gpr[{d}], ctx.gpr[{d}]);\n", .{ rt, name, ra, rb });
            }
            try recordCr(allocator, out, rc, false, rt);
        },
        .mulhw, .mulhwu, .mulld, .mulhd, .mulhdu, .divw, .divwu, .divd, .divdu => {
            const f = switch (op) {
                .mulhw => |v| v,
                .mulhwu => |v| v,
                .mulld => |v| v,
                .mulhd => |v| v,
                .mulhdu => |v| v,
                .divw => |v| v,
                .divwu => |v| v,
                .divd => |v| v,
                .divdu => |v| v,
                else => return error.UnsupportedOpcode,
            };
            const name = @tagName(std.meta.activeTag(op));
            try out.print(allocator, "    ctx.gpr[{d}] = ctx.{s}(ctx.gpr[{d}], ctx.gpr[{d}]);\n", .{ f.rt, name, f.ra, f.rb });
            try recordCr(allocator, out, f.rc, false, f.rt);
        },
        .slw, .srw, .sld, .srd, .srad => {
            const f = switch (op) {
                .slw => |v| v,
                .srw => |v| v,
                .sld => |v| v,
                .srd => |v| v,
                .srad => |v| v,
                else => return error.UnsupportedOpcode,
            };
            try out.print(allocator, "    ctx.gpr[{d}] = ctx.{s}(ctx.gpr[{d}], ctx.gpr[{d}]);\n", .{
                f.ra, @tagName(std.meta.activeTag(op)), f.rt, f.rb,
            });
            try recordCr(allocator, out, f.rc, false, f.ra);
        },
        .sradi => {
            try out.print(allocator, "    ctx.gpr[{d}] = ctx.sradi(ctx.gpr[{d}], {d});\n", .{ op.sradi.ra, op.sradi.rs, op.sradi.sh });
            try recordCr(allocator, out, op.sradi.rc, false, op.sradi.ra);
        },
        .xor_ => {
            try binop(allocator, out, "^", op.xor_.ra, op.xor_.rt, op.xor_.rb);
            try recordCr(allocator, out, op.xor_.rc, false, op.xor_.ra);
        },
        .andc => {
            try out.print(allocator, "    ctx.gpr[{d}] = ctx.gpr[{d}] & ~ctx.gpr[{d}];\n", .{ op.andc.ra, op.andc.rt, op.andc.rb });
            try recordCr(allocator, out, op.andc.rc, false, op.andc.ra);
        },
        .eqv => {
            try out.print(allocator, "    ctx.gpr[{d}] = ~(ctx.gpr[{d}] ^ ctx.gpr[{d}]);\n", .{ op.eqv.ra, op.eqv.rt, op.eqv.rb });
            try recordCr(allocator, out, op.eqv.rc, false, op.eqv.ra);
        },
        .nor_ => {
            try out.print(allocator, "    ctx.gpr[{d}] = ~(ctx.gpr[{d}] | ctx.gpr[{d}]);\n", .{ op.nor_.ra, op.nor_.rt, op.nor_.rb });
            try recordCr(allocator, out, op.nor_.rc, false, op.nor_.ra);
        },
        .orc => {
            try out.print(allocator, "    ctx.gpr[{d}] = ctx.gpr[{d}] | ~ctx.gpr[{d}];\n", .{ op.orc.ra, op.orc.rt, op.orc.rb });
            try recordCr(allocator, out, op.orc.rc, false, op.orc.ra);
        },
        .nand => {
            try out.print(allocator, "    ctx.gpr[{d}] = ~(ctx.gpr[{d}] & ctx.gpr[{d}]);\n", .{ op.nand.ra, op.nand.rt, op.nand.rb });
            try recordCr(allocator, out, op.nand.rc, false, op.nand.ra);
        },
        .cntlzd => {
            try out.print(allocator, "    ctx.gpr[{d}] = @clz(ctx.gpr[{d}]);\n", .{ op.cntlzd.ra, op.cntlzd.rt });
            try recordCr(allocator, out, op.cntlzd.rc, false, op.cntlzd.ra);
        },
        .cmpd => try out.print(allocator, "    ctx.setCr({d}, ctx.gpr[{d}], ctx.gpr[{d}], true);\n", .{ op.cmpd.crf, op.cmpd.ra, op.cmpd.rb }),
        .cmpld => try out.print(allocator, "    ctx.setCr({d}, ctx.gpr[{d}], ctx.gpr[{d}], false);\n", .{ op.cmpld.crf, op.cmpld.ra, op.cmpld.rb }),
        .twi => {
            try out.print(allocator, "    ctx.trapIf({d}, ctx.gpr[{d}], 0x{X:0>16}, 0x{X});\n", .{
                op.twi.to, op.twi.ra, sext(op.twi.imm), addr,
            });
        },
        .tw => {
            try out.print(allocator, "    ctx.trapIf({d}, ctx.gpr[{d}], ctx.gpr[{d}], 0x{X});\n", .{
                op.tw.to, op.tw.ra, op.tw.rb, addr,
            });
        },
        .mfspr => try out.print(allocator, "    ctx.gpr[{d}] = ctx.getSpr({d});\n", .{ op.mfspr.rt, op.mfspr.spr }),
        .mftb => try out.print(allocator, "    ctx.gpr[{d}] = ctx.getSpr({d});\n", .{ op.mftb.rt, op.mftb.spr }),
        .mtspr => try out.print(allocator, "    ctx.setSpr({d}, ctx.gpr[{d}]);\n", .{ op.mtspr.spr, op.mtspr.rt }),
        .mfmsr => try out.print(allocator, "    ctx.gpr[{d}] = ctx.msr;\n", .{op.mfmsr.rt}),
        .mtmsr, .mtmsrd => {
            const rt = switch (op) {
                .mtmsr => |f| f.rt,
                .mtmsrd => |f| f.rt,
                else => return error.UnsupportedOpcode,
            };
            try out.print(allocator, "    ctx.msr = ctx.gpr[{d}];\n", .{rt});
        },
        .mtocrf => try out.print(allocator, "    ctx.moveToCrf(0x{X:0>2}, ctx.gpr[{d}]);\n", .{ op.mtocrf.crm, op.mtocrf.rt }),
        .mfocrf => try out.print(allocator, "    ctx.gpr[{d}] = ctx.moveFromCrf(0x{X:0>2});\n", .{ op.mfocrf.rt, op.mfocrf.crm }),
        .lwsync, .sync, .isync, .eieio, .dcbt, .dcbtst, .dcbf, .dcbst, .dcbz, .icbi, .tlbiel, .tlbie, .slbmte, .slbia => {},
        .lwarx => |f| try indexedAtomic(allocator, out, f.rt, f.ra, f.rb, true),
        .stwcx => |f| try indexedAtomic(allocator, out, f.rt, f.ra, f.rb, false),
        .ldarx => |f| try indexedAtomic64(allocator, out, f.rt, f.ra, f.rb, true),
        .stdcx => |f| try indexedAtomic64(allocator, out, f.rt, f.ra, f.rb, false),
        .lhzu => try load(allocator, out, op, 2, true),
        .lhzux => try indexedUpdateLoad(allocator, out, op.lhzux.rt, op.lhzux.ra, op.lhzux.rb, 16),
        .lfsux => try fIndexedUpdateLoad(allocator, out, op.lfsux.frd, op.lfsux.fra, op.lfsux.frb),
        .lvsl => try out.print(allocator, "    ctx.vmx[{d}] = ctx.lvsl(@as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}])));\n", .{ op.lvsl.vd, op.lvsl.ra, op.lvsl.rb }),
        .lvsr => try out.print(allocator, "    ctx.vmx[{d}] = ctx.lvsr(@as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}])));\n", .{ op.lvsr.vd, op.lvsr.ra, op.lvsr.rb }),
        .lha => try loadSigned16(allocator, out, op.lha.rt, op.lha.ra, op.lha.imm, false),
        .lhau => try loadSigned16(allocator, out, op.lhau.rt, op.lhau.ra, op.lhau.imm, true),
        .stbu => try store(allocator, out, op, false),
        .sthu => try store(allocator, out, op, false),
        .sthx => try indexedStore(allocator, out, op.sthx.rt, op.sthx.ra, op.sthx.rb, 16),
        .ldx => try indexedLoad(allocator, out, op.ldx.rt, op.ldx.ra, op.ldx.rb, 8),
        .stdx => try indexedStore(allocator, out, op.stdx.rt, op.stdx.ra, op.stdx.rb, 64),
        .stbux => try indexedUpdateStore(allocator, out, op.stbux.rt, op.stbux.ra, op.stbux.rb, 8),
        .lwzux => try indexedUpdateLoad(allocator, out, op.lwzux.rt, op.lwzux.ra, op.lwzux.rb, 32),
        .lwax => try indexedLoadSigned32(allocator, out, op.lwax.rt, op.lwax.ra, op.lwax.rb),
        .stwux => try indexedUpdateStore(allocator, out, op.stwux.rt, op.stwux.ra, op.stwux.rb, 32),
        .sthux => try indexedUpdateStore(allocator, out, op.sthux.rt, op.sthux.ra, op.sthux.rb, 16),
        .stdux => try indexedUpdateStore(allocator, out, op.stdux.rt, op.stdux.ra, op.stdux.rb, 64),
        .lbzux => try indexedUpdateLoad(allocator, out, op.lbzux.rt, op.lbzux.ra, op.lbzux.rb, 8),
        .lwbrx => try indexedLoadBr(allocator, out, op.lwbrx.rt, op.lwbrx.ra, op.lwbrx.rb, 32),
        .lhbrx => try indexedLoadBr(allocator, out, op.lhbrx.rt, op.lhbrx.ra, op.lhbrx.rb, 16),
        .lhax => try indexedLoadSigned16(allocator, out, op.lhax.rt, op.lhax.ra, op.lhax.rb, false),
        .lhaux => try indexedLoadSigned16(allocator, out, op.lhaux.rt, op.lhaux.ra, op.lhaux.rb, true),
        .stwbrx => try indexedStoreBr(allocator, out, op.stwbrx.rt, op.stwbrx.ra, op.stwbrx.rb, 32),
        .sthbrx => try indexedStoreBr(allocator, out, op.sthbrx.rt, op.sthbrx.ra, op.sthbrx.rb, 16),
        .xoris => try out.print(allocator, "    ctx.gpr[{d}] = ctx.gpr[{d}] ^ (@as(u64, 0x{X:0>4}) << 16);\n", .{ op.xoris.ra, op.xoris.rt, op.xoris.imm }),
        .andis_dot => {
            try out.print(allocator, "    ctx.gpr[{d}] = ctx.gpr[{d}] & (@as(u64, 0x{X:0>4}) << 16);\n", .{ op.andis_dot.ra, op.andis_dot.rt, op.andis_dot.imm });
            try recordCr(allocator, out, true, false, op.andis_dot.ra);
        },
        .cr_op => {
            const f = op.cr_op;
            const expr = switch (f.kind) {
                .crand => "a & b",
                .crandc => "a & (~b)",
                .creqv => "~(a ^ b)",
                .crnand => "~(a & b)",
                .crnor => "~(a | b)",
                .cror => "a | b",
                .crorc => "a | (~b)",
                .crxor => "a ^ b",
            };
            try out.print(allocator, "    {{\n        const a = ctx.crBit({d});\n        const b = ctx.crBit({d});\n        ctx.setCrBit({d}, {s});\n    }}\n", .{ f.ba, f.bb, f.bt, expr });
        },
        .mcrf => try out.print(allocator, "    ctx.setCrField({d}, ctx.crField({d}));\n", .{ op.mcrf.crf_d, op.mcrf.crf_s }),
        else => return error.UnsupportedOpcode,
    }
}

fn recordCr(allocator: std.mem.Allocator, out: *std.ArrayList(u8), rc: bool, is_32: bool, reg: u8) !void {
    if (!rc) return;
    if (is_32) {
        try out.print(allocator, "    ctx.setCr32(0, ctx.gpr[{d}], 0, true);\n", .{reg});
    } else {
        try out.print(allocator, "    ctx.setCr(0, ctx.gpr[{d}], 0, true);\n", .{reg});
    }
}

fn rldicrMask(me: u6) u64 {
    if (me == 63) return 0xFFFFFFFFFFFFFFFF;
    return ~((@as(u64, 1) << @intCast(63 - @as(u6, me))) - 1);
}

fn gpr(reg: u8) u8 {
    return reg;
}

fn immAdd(allocator: std.mem.Allocator, out: *std.ArrayList(u8), rt: u8, ra: u8, value: u64) !void {
    if (ra == 0) {
        try out.print(allocator, "    ctx.gpr[{d}] = 0x{X:0>16};\n", .{ gpr(rt), value });
    } else {
        try out.print(allocator, "    ctx.gpr[{d}] = ctx.gpr[{d}] +% 0x{X:0>16};\n", .{ gpr(rt), gpr(ra), value });
    }
}

fn sext(value: i16) u64 {
    return @bitCast(@as(i64, value));
}

fn sext32(value: i16) u64 {
    return @bitCast(@as(i64, value) << 16);
}

fn immU32(allocator: std.mem.Allocator, out: *std.ArrayList(u8), comptime op: []const u8, rt: u8, ra: u8, imm: u16) !void {
    try out.print(allocator, "    ctx.gpr[{d}] = ctx.gpr[{d}] {s} 0x{X};\n", .{ gpr(rt), gpr(ra), op, imm });
}

fn immU32Shifted(allocator: std.mem.Allocator, out: *std.ArrayList(u8), rt: u8, ra: u8, imm: u16) !void {
    try out.print(allocator, "    ctx.gpr[{d}] = ctx.gpr[{d}] | 0x{X:0>8};\n", .{ gpr(rt), gpr(ra), @as(u32, imm) << 16 });
}

fn binop(allocator: std.mem.Allocator, out: *std.ArrayList(u8), comptime op: []const u8, rt: u8, ra: u8, rb: u8) !void {
    try out.print(allocator, "    ctx.gpr[{d}] = ctx.gpr[{d}] {s} ctx.gpr[{d}];\n", .{ gpr(rt), gpr(ra), op, gpr(rb) });
}

fn subf(allocator: std.mem.Allocator, out: *std.ArrayList(u8), rt: u8, ra: u8, rb: u8) !void {
    try out.print(allocator, "    ctx.gpr[{d}] = ctx.gpr[{d}] -% ctx.gpr[{d}];\n", .{ gpr(rt), gpr(rb), gpr(ra) });
}

fn mov(allocator: std.mem.Allocator, out: *std.ArrayList(u8), rt: u8, comptime field: []const u8) !void {
    try out.print(allocator, "    ctx.gpr[{d}] = ctx.{s};\n", .{ gpr(rt), field });
}

fn movTo(allocator: std.mem.Allocator, out: *std.ArrayList(u8), comptime field: []const u8, rt: u8) !void {
    try out.print(allocator, "    ctx.{s} = @truncate(ctx.gpr[{d}]);\n", .{ field, gpr(rt) });
}

fn load(allocator: std.mem.Allocator, out: *std.ArrayList(u8), op: insn, comptime size: u8, update: bool) !void {
    const rt: u8, const ra: u8, const imm: i16 = switch (op) {
        .lwz => |f| .{ f.rt, f.ra, f.imm },
        .lwzu => |f| .{ f.rt, f.ra, f.imm },
        .lbz => |f| .{ f.rt, f.ra, f.imm },
        .lbzu => |f| .{ f.rt, f.ra, f.imm },
        .lhzu => |f| .{ f.rt, f.ra, f.imm },
        else => return error.UnsupportedOpcode,
    };
    try printAddr(allocator, out, size * 8, "load", true, rt, ra, imm, update);
}

fn store(allocator: std.mem.Allocator, out: *std.ArrayList(u8), op: insn, update: bool) !void {
    const rt: u8, const ra: u8, const imm: i16, const size: u8 = switch (op) {
        .stw => |f| .{ f.rt, f.ra, f.imm, 32 },
        .stwu => |f| .{ f.rt, f.ra, f.imm, 32 },
        .stb => |f| .{ f.rt, f.ra, f.imm, 8 },
        .stbu => |f| .{ f.rt, f.ra, f.imm, 8 },
        .sthu => |f| .{ f.rt, f.ra, f.imm, 16 },
        else => return error.UnsupportedOpcode,
    };
    try printAddr(allocator, out, size, "store", false, rt, ra, imm, update);
}

fn printAddr(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    bits: u8,
    comptime kind: []const u8,
    is_load: bool,
    rt: u8,
    ra: u8,
    imm: i16,
    update: bool,
) !void {
    const value = @as(u32, @bitCast(@as(i32, imm)));
    if (ra == 0) {
        if (is_load) {
            try out.print(allocator, "    ctx.gpr[{d}] = ctx.{s}{d}(0 +% 0x{X:0>8});\n", .{ rt, kind, bits, value });
        } else {
            try out.print(allocator, "    ctx.{s}{d}(0 +% 0x{X:0>8}, ctx.gpr[{d}]);\n", .{ kind, bits, value, rt });
        }
        return;
    }

    if (!update) {
        if (is_load) {
            try out.print(allocator, "    ctx.gpr[{d}] = ctx.{s}{d}(@as(u32, @truncate(ctx.gpr[{d}])) +% 0x{X:0>8});\n", .{ rt, kind, bits, ra, value });
        } else {
            try out.print(allocator, "    ctx.{s}{d}(@as(u32, @truncate(ctx.gpr[{d}])) +% 0x{X:0>8}, ctx.gpr[{d}]);\n", .{ kind, bits, ra, value, rt });
        }
        return;
    }

    try out.appendSlice(allocator, "    {\n");
    try out.print(allocator, "        const ea: u32 = @as(u32, @truncate(ctx.gpr[{d}])) +% 0x{X:0>8};\n", .{ ra, value });
    if (is_load) {
        try out.print(allocator, "        ctx.gpr[{d}] = ctx.{s}{d}(ea);\n", .{ rt, kind, bits });
    } else {
        try out.print(allocator, "        ctx.{s}{d}(ea, ctx.gpr[{d}]);\n", .{ kind, bits, rt });
    }
    try out.print(allocator, "        ctx.gpr[{d}] = ea;\n    }}\n", .{ra});
}

fn vmem(allocator: std.mem.Allocator, out: *std.ArrayList(u8), form: ppc.decode.VMemForm, is_load: bool) !void {
    try out.appendSlice(allocator, "    {\n");
    if (form.ra == 0) {
        try out.print(allocator, "        const ea: u32 = @as(u32, @truncate(ctx.gpr[{d}]));\n", .{form.rb});
    } else {
        try out.print(allocator, "        const ea: u32 = @as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}]));\n", .{ form.ra, form.rb });
    }
    if (is_load) {
        try out.print(allocator, "        ctx.vmx[{d}] = ctx.loadVmx(ea);\n", .{form.vd});
    } else {
        try out.print(allocator, "        ctx.storeVmx(ea, ctx.vmx[{d}]);\n", .{form.vd});
    }
    try out.appendSlice(allocator, "    }\n");
}

fn fBinop(allocator: std.mem.Allocator, out: *std.ArrayList(u8), op: []const u8, frd: u8, fra: u8, frb: u8) !void {
    try out.print(allocator, "    ctx.fpr[{d}] = ctx.fpr[{d}] {s} ctx.fpr[{d}];\n", .{ frd, fra, op, frb });
}

fn fLoad(allocator: std.mem.Allocator, out: *std.ArrayList(u8), frd: u8, ra: u8, imm: i16) !void {
    const value = @as(u32, @bitCast(@as(i32, imm)));
    if (ra == 0) {
        try out.print(allocator, "    ctx.fpr[{d}] = @floatCast(@as(f32, @bitCast(@as(u32, @truncate(ctx.load32(0 +% 0x{X:0>8}))))));\n", .{ frd, value });
    } else {
        try out.print(allocator, "    ctx.fpr[{d}] = @floatCast(@as(f32, @bitCast(@as(u32, @truncate(ctx.load32(@as(u32, @truncate(ctx.gpr[{d}])) +% 0x{X:0>8}))))));\n", .{ frd, ra, value });
    }
}

fn fStore(allocator: std.mem.Allocator, out: *std.ArrayList(u8), frd: u8, ra: u8, imm: i16) !void {
    const value = @as(u32, @bitCast(@as(i32, imm)));
    if (ra == 0) {
        try out.print(allocator, "    ctx.store32(0 +% 0x{X:0>8}, @as(u32, @bitCast(@as(f32, @floatCast(ctx.fpr[{d}])))));\n", .{ value, frd });
    } else {
        try out.print(allocator, "    ctx.store32(@as(u32, @truncate(ctx.gpr[{d}])) +% 0x{X:0>8}, @as(u32, @bitCast(@as(f32, @floatCast(ctx.fpr[{d}])))));\n", .{ ra, value, frd });
    }
}

fn fma(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    comptime ty: []const u8,
    comptime op: []const u8,
    frd: u8,
    fra: u8,
    frc: u8,
    frb: u8,
    negate: bool,
) !void {
    if (std.mem.eql(u8, ty, "f32")) {
        if (negate) {
            try out.print(allocator, "    ctx.fpr[{d}] = @floatCast(-(@as(f32, @floatCast(ctx.fpr[{d}])) * @as(f32, @floatCast(ctx.fpr[{d}])) {s} @as(f32, @floatCast(ctx.fpr[{d}]))));\n", .{ frd, fra, frc, op, frb });
        } else {
            try out.print(allocator, "    ctx.fpr[{d}] = @floatCast(@as(f32, @floatCast(ctx.fpr[{d}])) * @as(f32, @floatCast(ctx.fpr[{d}])) {s} @as(f32, @floatCast(ctx.fpr[{d}])));\n", .{ frd, fra, frc, op, frb });
        }
        return;
    }
    if (negate) {
        try out.print(allocator, "    ctx.fpr[{d}] = -(ctx.fpr[{d}] * ctx.fpr[{d}] {s} ctx.fpr[{d}]);\n", .{ frd, fra, frc, op, frb });
    } else {
        try out.print(allocator, "    ctx.fpr[{d}] = ctx.fpr[{d}] * ctx.fpr[{d}] {s} ctx.fpr[{d}];\n", .{ frd, fra, frc, op, frb });
    }
}

fn fLoadUpdate(allocator: std.mem.Allocator, out: *std.ArrayList(u8), frd: u8, ra: u8, imm: i16, comptime bits: u8) !void {
    const value = @as(u32, @bitCast(@as(i32, imm)));
    try out.appendSlice(allocator, "    {\n");
    try out.print(allocator, "        const ea: u32 = @as(u32, @truncate(ctx.gpr[{d}])) +% 0x{X:0>8};\n", .{ ra, value });
    if (bits == 32) {
        try out.print(allocator, "        ctx.fpr[{d}] = @floatCast(@as(f32, @bitCast(@as(u32, @truncate(ctx.load32(ea))))));\n", .{frd});
    } else {
        try out.print(allocator, "        ctx.fpr[{d}] = @bitCast(ctx.load64(ea));\n", .{frd});
    }
    try out.print(allocator, "        ctx.gpr[{d}] = ea;\n    }}\n", .{ra});
}

fn fStoreUpdate(allocator: std.mem.Allocator, out: *std.ArrayList(u8), frd: u8, ra: u8, imm: i16, comptime bits: u8) !void {
    const value = @as(u32, @bitCast(@as(i32, imm)));
    try out.appendSlice(allocator, "    {\n");
    try out.print(allocator, "        const ea: u32 = @as(u32, @truncate(ctx.gpr[{d}])) +% 0x{X:0>8};\n", .{ ra, value });
    if (bits == 32) {
        try out.print(allocator, "        ctx.store32(ea, @as(u32, @bitCast(@as(f32, @floatCast(ctx.fpr[{d}])))));\n", .{frd});
    } else {
        try out.print(allocator, "        ctx.store64(ea, @bitCast(ctx.fpr[{d}]));\n", .{frd});
    }
    try out.print(allocator, "        ctx.gpr[{d}] = ea;\n    }}\n", .{ra});
}

fn fIndexedLoad(allocator: std.mem.Allocator, out: *std.ArrayList(u8), frd: u8, ra: u8, rb: u8, comptime bits: u8) !void {
    if (ra == 0) {
        if (bits == 32) {
            try out.print(allocator, "    ctx.fpr[{d}] = @floatCast(@as(f32, @bitCast(@as(u32, @truncate(ctx.load32(@as(u32, @truncate(ctx.gpr[{d}]))))))));\n", .{ frd, rb });
        } else {
            try out.print(allocator, "    ctx.fpr[{d}] = @bitCast(ctx.load64(@as(u32, @truncate(ctx.gpr[{d}]))));\n", .{ frd, rb });
        }
        return;
    }
    if (bits == 32) {
        try out.print(allocator, "    ctx.fpr[{d}] = @floatCast(@as(f32, @bitCast(@as(u32, @truncate(ctx.load32(@as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}]))))))));\n", .{ frd, ra, rb });
    } else {
        try out.print(allocator, "    ctx.fpr[{d}] = @bitCast(ctx.load64(@as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}]))));\n", .{ frd, ra, rb });
    }
}

fn fIndexedStore(allocator: std.mem.Allocator, out: *std.ArrayList(u8), frd: u8, ra: u8, rb: u8, comptime bits: u8) !void {
    if (ra == 0) {
        if (bits == 32) {
            try out.print(allocator, "    ctx.store32(@as(u32, @truncate(ctx.gpr[{d}])), @as(u32, @bitCast(@as(f32, @floatCast(ctx.fpr[{d}])))));\n", .{ rb, frd });
        } else {
            try out.print(allocator, "    ctx.store64(@as(u32, @truncate(ctx.gpr[{d}])), @bitCast(ctx.fpr[{d}]));\n", .{ rb, frd });
        }
        return;
    }
    if (bits == 32) {
        try out.print(allocator, "    ctx.store32(@as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}])), @as(u32, @bitCast(@as(f32, @floatCast(ctx.fpr[{d}])))));\n", .{ ra, rb, frd });
    } else {
        try out.print(allocator, "    ctx.store64(@as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}])), @bitCast(ctx.fpr[{d}]));\n", .{ ra, rb, frd });
    }
}

fn load64(allocator: std.mem.Allocator, out: *std.ArrayList(u8), rt: u8, ra: u8, ds: i16, update: bool) !void {
    const value = @as(u32, @bitCast(@as(i32, ds)));
    if (ra == 0) {
        try out.print(allocator, "    ctx.gpr[{d}] = ctx.load64(0 +% 0x{X:0>8});\n", .{ rt, value });
        return;
    }
    if (!update) {
        try out.print(allocator, "    ctx.gpr[{d}] = ctx.load64(@as(u32, @truncate(ctx.gpr[{d}])) +% 0x{X:0>8});\n", .{ rt, ra, value });
        return;
    }
    try out.appendSlice(allocator, "    {\n");
    try out.print(allocator, "        const ea: u32 = @as(u32, @truncate(ctx.gpr[{d}])) +% 0x{X:0>8};\n", .{ ra, value });
    try out.print(allocator, "        ctx.gpr[{d}] = ctx.load64(ea);\n", .{rt});
    try out.print(allocator, "        ctx.gpr[{d}] = ea;\n    }}\n", .{ra});
}

fn store64(allocator: std.mem.Allocator, out: *std.ArrayList(u8), rt: u8, ra: u8, ds: i16, update: bool) !void {
    const value = @as(u32, @bitCast(@as(i32, ds)));
    if (ra == 0) {
        try out.print(allocator, "    ctx.store64(0 +% 0x{X:0>8}, ctx.gpr[{d}]);\n", .{ value, rt });
        return;
    }
    if (!update) {
        try out.print(allocator, "    ctx.store64(@as(u32, @truncate(ctx.gpr[{d}])) +% 0x{X:0>8}, ctx.gpr[{d}]);\n", .{ ra, value, rt });
        return;
    }
    try out.appendSlice(allocator, "    {\n");
    try out.print(allocator, "        const ea: u32 = @as(u32, @truncate(ctx.gpr[{d}])) +% 0x{X:0>8};\n", .{ ra, value });
    try out.print(allocator, "        ctx.store64(ea, ctx.gpr[{d}]);\n", .{rt});
    try out.print(allocator, "        ctx.gpr[{d}] = ea;\n    }}\n", .{ra});
}

fn indexedLoad(allocator: std.mem.Allocator, out: *std.ArrayList(u8), rt: u8, ra: u8, rb: u8, comptime size: u8) !void {
    if (ra == 0) {
        try out.print(allocator, "    ctx.gpr[{d}] = ctx.load{d}(@as(u32, @truncate(ctx.gpr[{d}])));\n", .{ rt, size * 8, rb });
    } else {
        try out.print(allocator, "    ctx.gpr[{d}] = ctx.load{d}(@as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}])));\n", .{ rt, size * 8, ra, rb });
    }
}

fn indexedStore(allocator: std.mem.Allocator, out: *std.ArrayList(u8), rt: u8, ra: u8, rb: u8, comptime bits: u8) !void {
    if (ra == 0) {
        try out.print(allocator, "    ctx.store{d}(@as(u32, @truncate(ctx.gpr[{d}])), ctx.gpr[{d}]);\n", .{ bits, rb, rt });
    } else {
        try out.print(allocator, "    ctx.store{d}(@as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}])), ctx.gpr[{d}]);\n", .{ bits, ra, rb, rt });
    }
}

fn indexedLoadBr(allocator: std.mem.Allocator, out: *std.ArrayList(u8), rt: u8, ra: u8, rb: u8, comptime bits: u8) !void {
    if (ra == 0) {
        try out.print(allocator, "    ctx.gpr[{d}] = ctx.load{d}br(@as(u32, @truncate(ctx.gpr[{d}])));\n", .{ rt, bits, rb });
    } else {
        try out.print(allocator, "    ctx.gpr[{d}] = ctx.load{d}br(@as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}])));\n", .{ rt, bits, ra, rb });
    }
}

fn indexedLoadSigned32(allocator: std.mem.Allocator, out: *std.ArrayList(u8), rt: u8, ra: u8, rb: u8) !void {
    if (ra == 0) {
        try out.print(allocator, "    ctx.gpr[{d}] = @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(ctx.load32(@as(u32, @truncate(ctx.gpr[{d}]))))))));\n", .{ rt, rb });
    } else {
        try out.print(allocator, "    ctx.gpr[{d}] = @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(ctx.load32(@as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}])))))))));\n", .{ rt, ra, rb });
    }
}

fn fIndexedUpdateLoad64(allocator: std.mem.Allocator, out: *std.ArrayList(u8), frd: u8, ra: u8, rb: u8) !void {
    try out.appendSlice(allocator, "    {\n");
    try out.print(allocator, "        const ea: u32 = @as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}]));\n", .{ ra, rb });
    try out.print(allocator, "        ctx.fpr[{d}] = @bitCast(ctx.load64(ea));\n", .{frd});
    try out.print(allocator, "        ctx.gpr[{d}] = ea;\n    }}\n", .{ra});
}

fn indexedLoadSigned16(allocator: std.mem.Allocator, out: *std.ArrayList(u8), rt: u8, ra: u8, rb: u8, update: bool) !void {
    if (update) {
        try out.appendSlice(allocator, "    {\n");
        try out.print(allocator, "        const ea: u32 = @as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}]));\n", .{ ra, rb });
        try out.print(allocator, "        ctx.gpr[{d}] = @bitCast(@as(i64, @as(i16, @bitCast(@as(u16, @truncate(ctx.load16(ea)))))));\n", .{rt});
        try out.print(allocator, "        ctx.gpr[{d}] = ea;\n    }}\n", .{ra});
        return;
    }
    if (ra == 0) {
        try out.print(allocator, "    ctx.gpr[{d}] = @bitCast(@as(i64, @as(i16, @bitCast(@as(u16, @truncate(ctx.load16(@as(u32, @truncate(ctx.gpr[{d}])))))))));\n", .{ rt, rb });
    } else {
        try out.print(allocator, "    ctx.gpr[{d}] = @bitCast(@as(i64, @as(i16, @bitCast(@as(u16, @truncate(ctx.load16(@as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}])))))))));\n", .{ rt, ra, rb });
    }
}

fn indexedStoreBr(allocator: std.mem.Allocator, out: *std.ArrayList(u8), rt: u8, ra: u8, rb: u8, comptime bits: u8) !void {
    if (ra == 0) {
        try out.print(allocator, "    ctx.store{d}br(@as(u32, @truncate(ctx.gpr[{d}])), ctx.gpr[{d}]);\n", .{ bits, rb, rt });
    } else {
        try out.print(allocator, "    ctx.store{d}br(@as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}])), ctx.gpr[{d}]);\n", .{ bits, ra, rb, rt });
    }
}

fn indexedAtomic(allocator: std.mem.Allocator, out: *std.ArrayList(u8), rt: u8, ra: u8, rb: u8, comptime is_load: bool) !void {
    if (ra == 0) {
        if (is_load) {
            try out.print(allocator, "    ctx.gpr[{d}] = ctx.lwarx(@as(u32, @truncate(ctx.gpr[{d}])));\n", .{ rt, rb });
        } else {
            try out.print(allocator, "    ctx.stwcx(@as(u32, @truncate(ctx.gpr[{d}])), ctx.gpr[{d}]);\n", .{ rb, rt });
        }
        return;
    }
    if (is_load) {
        try out.print(allocator, "    ctx.gpr[{d}] = ctx.lwarx(@as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}])));\n", .{ rt, ra, rb });
    } else {
        try out.print(allocator, "    ctx.stwcx(@as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}])), ctx.gpr[{d}]);\n", .{ ra, rb, rt });
    }
}

fn indexedAtomic64(allocator: std.mem.Allocator, out: *std.ArrayList(u8), rt: u8, ra: u8, rb: u8, comptime is_load: bool) !void {
    if (ra == 0) {
        if (is_load) {
            try out.print(allocator, "    ctx.gpr[{d}] = ctx.ldarx(@as(u32, @truncate(ctx.gpr[{d}])));\n", .{ rt, rb });
        } else {
            try out.print(allocator, "    ctx.stdcx(@as(u32, @truncate(ctx.gpr[{d}])), ctx.gpr[{d}]);\n", .{ rb, rt });
        }
        return;
    }
    if (is_load) {
        try out.print(allocator, "    ctx.gpr[{d}] = ctx.ldarx(@as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}])));\n", .{ rt, ra, rb });
    } else {
        try out.print(allocator, "    ctx.stdcx(@as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}])), ctx.gpr[{d}]);\n", .{ ra, rb, rt });
    }
}

fn fIndexedUpdateLoad(allocator: std.mem.Allocator, out: *std.ArrayList(u8), frd: u8, ra: u8, rb: u8) !void {
    try out.appendSlice(allocator, "    {\n");
    try out.print(allocator, "        const ea: u32 = @as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}]));\n", .{ ra, rb });
    try out.print(allocator, "        ctx.fpr[{d}] = @floatCast(@as(f32, @bitCast(@as(u32, @truncate(ctx.load32(ea))))));\n", .{frd});
    try out.print(allocator, "        ctx.gpr[{d}] = ea;\n    }}\n", .{ra});
}

fn indexedUpdateLoad(allocator: std.mem.Allocator, out: *std.ArrayList(u8), rt: u8, ra: u8, rb: u8, comptime bits: u8) !void {
    try out.appendSlice(allocator, "    {\n");
    try out.print(allocator, "        const ea: u32 = @as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}]));\n", .{ ra, rb });
    try out.print(allocator, "        ctx.gpr[{d}] = ctx.load{d}(ea);\n", .{ rt, bits });
    try out.print(allocator, "        ctx.gpr[{d}] = ea;\n    }}\n", .{ra});
}

fn indexedUpdateStore(allocator: std.mem.Allocator, out: *std.ArrayList(u8), rt: u8, ra: u8, rb: u8, comptime bits: u8) !void {
    try out.appendSlice(allocator, "    {\n");
    try out.print(allocator, "        const ea: u32 = @as(u32, @truncate(ctx.gpr[{d}])) +% @as(u32, @truncate(ctx.gpr[{d}]));\n", .{ ra, rb });
    try out.print(allocator, "        ctx.store{d}(ea, ctx.gpr[{d}]);\n", .{ bits, rt });
    try out.print(allocator, "        ctx.gpr[{d}] = ea;\n    }}\n", .{ra});
}

fn loadSigned16(allocator: std.mem.Allocator, out: *std.ArrayList(u8), rt: u8, ra: u8, imm: i16, update: bool) !void {
    const value = @as(u32, @bitCast(@as(i32, imm)));
    if (ra == 0) {
        try out.print(allocator, "    ctx.gpr[{d}] = @bitCast(@as(i64, @as(i16, @bitCast(@as(u16, @truncate(ctx.load16(0 +% 0x{X:0>8})))))));\n", .{ rt, value });
        return;
    }
    if (!update) {
        try out.print(allocator, "    ctx.gpr[{d}] = @bitCast(@as(i64, @as(i16, @bitCast(@as(u16, @truncate(ctx.load16(@as(u32, @truncate(ctx.gpr[{d}])) +% 0x{X:0>8})))))));\n", .{ rt, ra, value });
        return;
    }
    try out.appendSlice(allocator, "    {\n");
    try out.print(allocator, "        const ea: u32 = @as(u32, @truncate(ctx.gpr[{d}])) +% 0x{X:0>8};\n", .{ ra, value });
    try out.print(allocator, "        ctx.gpr[{d}] = @bitCast(@as(i64, @as(i16, @bitCast(@as(u16, @truncate(ctx.load16(ea)))))));\n", .{rt});
    try out.print(allocator, "        ctx.gpr[{d}] = ea;\n    }}\n", .{ra});
}

fn compareImm(allocator: std.mem.Allocator, out: *std.ArrayList(u8), crf: u3, ra: u8, imm: anytype, signed: bool) !void {
    try out.print(allocator, "    ctx.setCr32({d}, ctx.gpr[{d}], 0x{X:0>16}, {s});\n", .{
        crf, gpr(ra), @as(u64, @bitCast(@as(i64, imm))), if (signed) "true" else "false",
    });
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

test "golden function" {
    const words = [_]u32{ 0x38600001, 0x914b0014, 0x4e800020 };
    const text = try function(testing.allocator, &words, .{ .addr = 0x100 });
    defer testing.allocator.free(text);

    try testing.expectEqualStrings(
        \\pub fn g_00000100(ctx: *Ctx) callconv(.c) void {
        \\    if (ctx.depth >= Ctx.max_call_depth) {
        \\        ctx.fault = .{ .kind = .recursion, .addr = 0x100 };
        \\        return;
        \\    }
        \\    ctx.depth += 1;
        \\    defer ctx.depth -= 1;
        \\    // 0x00000100
        \\    if (ctx.budget != 0) {
        \\        ctx.budget -= 1;
        \\        if (ctx.budget == 0) return;
        \\    }
        \\    ctx.gpr[3] = 0x0000000000000001;
        \\    // 0x00000104
        \\    if (ctx.budget != 0) {
        \\        ctx.budget -= 1;
        \\        if (ctx.budget == 0) return;
        \\    }
        \\    ctx.store32(@as(u32, @truncate(ctx.gpr[11])) +% 0x00000014, ctx.gpr[10]);
        \\    // 0x00000108
        \\    if (ctx.budget != 0) {
        \\        ctx.budget -= 1;
        \\        if (ctx.budget == 0) return;
        \\    }
        \\    return;
        \\}
        \\
    , text);
}

test "vmx bitwise ops lower to the vector helpers" {
    const words = [_]u32{ 0x10221cc4, 0x4e800020 };
    const text = try function(testing.allocator, &words, .{ .addr = 0 });
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "ctx.vmx[1] = ctx.vxor(ctx.vmx[2], ctx.vmx[3]);") != null);
}

test "bctrl lowers to an indirect call through ctr" {
    const words = [_]u32{ 0x4e800421, 0x4e800020 };
    const text = try function(testing.allocator, &words, .{ .addr = 0x100 });
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "const target: u32 = ctx.ctr;") != null);
    try testing.expect(std.mem.indexOf(u8, text, "dispatch(target, ctx)") != null);
}

test "bctr and bcctr lower through ctr" {
    const bctr = [_]u32{ 0x4e800420, 0x4e800020 }; // bctr; blr
    const bctr_text = try function(testing.allocator, &bctr, .{ .addr = 0x100 });
    defer testing.allocator.free(bctr_text);
    try testing.expect(std.mem.indexOf(u8, bctr_text, "dispatch(ctx.ctr, ctx)") != null);
    try testing.expect(supportsAt(try ppc.decode.decode(0x4e800420), 0, 0, 4));

    const bcctr = [_]u32{ 0x4d800421, 0x4e800020 }; // bcctrl 12,0; blr
    const bcctr_text = try function(testing.allocator, &bcctr, .{ .addr = 0x100 });
    defer testing.allocator.free(bcctr_text);
    try testing.expect(std.mem.indexOf(u8, bcctr_text, "ctx.lr = 0x104;") != null);
    try testing.expect(std.mem.indexOf(u8, bcctr_text, "const target: u32 = ctx.ctr;") != null);
    try testing.expect(std.mem.indexOf(u8, bcctr_text, "dispatch(target, ctx)") != null);
}

test "conditional bclr lowers through branch" {
    const words = [_]u32{ 0x4d820020, 0x4e800020 }; // bclr 12,2
    const text = try function(testing.allocator, &words, .{ .addr = 0x100 });
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "if (ctx.branch(12, 2)) return;") != null);
}

test "absolute linked branch dispatches its absolute target" {
    const words = [_]u32{ 0x42000003, 0x4e800020 }; // bc 16,0,0 absolute, link
    const text = try function(testing.allocator, &words, .{ .addr = 0x100 });
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "dispatch(0x0, ctx)") != null);
}

test "float arithmetic lowers to fpr operations" {
    const words = [_]u32{ 0xfc22182a, 0x4e800020 };
    const text = try function(testing.allocator, &words, .{ .addr = 0 });
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "ctx.fpr[1] = ctx.fpr[2] + ctx.fpr[3];") != null);
}

test "forward branch targets the labelled address" {
    // b +8 at 0x100 skips the nop at 0x104.
    const words = [_]u32{ 0x48000008, 0x60000000, 0x4e800020 };
    const text = try function(testing.allocator, &words, .{ .addr = 0x100 });
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "pc = 0x108;") != null);
}

test "backward branch is accepted" {
    // nop; b -4 at 0x104; blr.
    const words = [_]u32{ 0x60000000, 0x4BFFFFFC, 0x4e800020 };
    const text = try function(testing.allocator, &words, .{ .addr = 0x100 });
    defer testing.allocator.free(text);
}

test "a branch outside the function becomes a tail call" {
    // b +0x100 at 0x100 leaves the three-word function.
    const words = [_]u32{ 0x48000100, 0x60000000, 0x4e800020 };
    const text = try function(testing.allocator, &words, .{ .addr = 0x100 });
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "dispatch(0x200, ctx)") != null);
}

test "bl calls through dispatch" {
    // bl +4 at 0x100 targets 0x104.
    const words = [_]u32{ 0x48000005, 0x4e800020 };
    const text = try function(testing.allocator, &words, .{ .addr = 0x100 });
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "ctx.lr = 0x104;") != null);
    try testing.expect(std.mem.indexOf(u8, text, "dispatch(0x104, ctx)") != null);
}

test "mullw keeps the low 32 bits" {
    const words = [_]u32{ 0x7c6321d6, 0x4e800020 }; // mullw r3,r3,r4
    const text = try function(testing.allocator, &words, .{ .addr = 0x100 });
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "@as(u32, @truncate(ctx.gpr[3] *% ctx.gpr[4]))") != null);
}

test "mulli keeps the full 64-bit product" {
    const words = [_]u32{ 0x1c633039, 0x4e800020 }; // mulli r3,r3,12345
    const text = try function(testing.allocator, &words, .{ .addr = 0x100 });
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "@as(i64, 12345)") != null);
}

test "fctiwz leaves integer bits in the fpr" {
    const words = [_]u32{ 0xfc60081e, 0x4e800020 }; // fctiwz f3,f1
    const text = try function(testing.allocator, &words, .{ .addr = 0x100 });
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "ctx.fpr[3] = ctx.fctiwz(ctx.fpr[1]);") != null);
}

test "cmpwi uses the 32-bit compare helper" {
    const words = [_]u32{ 0x2c030000, 0x4e800020 }; // cmpwi r3,0
    const text = try function(testing.allocator, &words, .{ .addr = 0x100 });
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "ctx.setCr32(0, ctx.gpr[3], 0x0000000000000000, true);") != null);
}

test "record forms update CR0" {
    const sub = [_]u32{ 0x7c662851, 0x4e800020 }; // subf. r3,r6,r5
    const sub_text = try function(testing.allocator, &sub, .{ .addr = 0x100 });
    defer testing.allocator.free(sub_text);
    try testing.expect(std.mem.indexOf(u8, sub_text, "ctx.setCr(0, ctx.gpr[3], 0, true);") != null);

    const rot = [_]u32{ 0x5483003f, 0x4e800020 }; // rlwinm. r3,r4,0,0,31
    const rot_text = try function(testing.allocator, &rot, .{ .addr = 0x100 });
    defer testing.allocator.free(rot_text);
    try testing.expect(std.mem.indexOf(u8, rot_text, "ctx.setCr32(0, ctx.gpr[3], 0, true);") != null);
}

test "rlwinm masks in PPC bit order" {
    const words = [_]u32{ 0x54a0e13f, 0x4e800020 }; // rlwinm. r0,r5,28,4,31
    const text = try function(testing.allocator, &words, .{ .addr = 0x100 });
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "& 0x0FFFFFFF") != null);
}

test "shift lowers into the RA destination" {
    const words = [_]u32{ 0x7D231C30, 0x4e800020 }; // srw 3,9,3
    const text = try function(testing.allocator, &words, .{ .addr = 0x100 });
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "ctx.gpr[3] = ctx.srw(ctx.gpr[9], ctx.gpr[3]);") != null);
}

test "every supported vector tag lowers" {
    const words = [_]u32{
        0x10221c04, // vand
        0x10221806, // vcmpequb
        0x10221a06, // vcmpgtub
        0x1022184a, // vsubfp
        0x10221884, // vrlw
        0x1022192b, // vperm
        0x102220ee, // vmaddfp
        0x1025038c, // vspltisw
        0x4e800020,
    };
    const text = try function(testing.allocator, &words, .{ .addr = 0x100 });
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "ctx.vand") != null);
    try testing.expect(std.mem.indexOf(u8, text, "ctx.vperm") != null);
    try testing.expect(std.mem.indexOf(u8, text, "ctx.vspltisw") != null);
}

test "vmx compare and add lower through vector helpers" {
    const words = [_]u32{ 0x13E05C07, 0x101FF880, 0x4e800020 };
    const text = try function(testing.allocator, &words, .{ .addr = 0x100 });
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "ctx.vmx[31] = ctx.vmxCmp(0, ctx.vmx[0], ctx.vmx[11]);") != null);
    try testing.expect(std.mem.indexOf(u8, text, "ctx.vmx[0] = ctx.vadduwm(ctx.vmx[31], ctx.vmx[31]);") != null);
}

test "fmul reads the FRC operand and fmadd reads both" {
    const mul = [_]u32{ 0xFC210332, 0x4e800020 }; // fmul f1,f1,f12
    const mul_text = try function(testing.allocator, &mul, .{ .addr = 0x100 });
    defer testing.allocator.free(mul_text);
    try testing.expect(std.mem.indexOf(u8, mul_text, "ctx.fpr[1] = ctx.fpr[1] * ctx.fpr[12];") != null);

    const add = [_]u32{ 0xFC21483A, 0x4e800020 }; // fmadd f1,f1,f0,f9
    const add_text = try function(testing.allocator, &add, .{ .addr = 0x100 });
    defer testing.allocator.free(add_text);
    try testing.expect(std.mem.indexOf(u8, add_text, "ctx.fpr[1] = ctx.fpr[1] * ctx.fpr[0] + ctx.fpr[9];") != null);
}

test "addic and subfe lower through the carry helpers" {
    const words = [_]u32{ 0x30630001, 0x7cc42910, 0x4e800020 };
    const text = try function(testing.allocator, &words, .{ .addr = 0x100 });
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "ctx.addic(ctx.gpr[3], 1)") != null);
    try testing.expect(std.mem.indexOf(u8, text, "ctx.subfe(ctx.gpr[4], ctx.gpr[5])") != null);
}

test "ld lowers with the byte offset" {
    const words = [_]u32{ 0xE8C40008, 0x4e800020 }; // ld r6,8(r4)
    const text = try function(testing.allocator, &words, .{ .addr = 0x100 });
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "+% 0x00000008") != null);
}

test "lwa closes every conversion" {
    const words = [_]u32{ 0xe97b0002, 0x4e800020 }; // lwa r11,0(r27)
    const text = try function(testing.allocator, &words, .{ .addr = 0x100 });
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "@bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(ctx.load32(@as(u32, @truncate(ctx.gpr[27])) +% 0x00000000)))))))") != null);
}

test "rldicr uses the six-bit fields" {
    const words = [_]u32{ 0x78834506, 0x4e800020 }; // rldicr r3,r4,40,20
    const text = try function(testing.allocator, &words, .{ .addr = 0x100 });
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "std.math.rotl(u64, ctx.gpr[4], 40)") != null);
}
