//! Zig emitter for the P0 integer subset.
//!
//! Branches inside a function, float and VMX instructions are refused by name; the slice
//! selector must only choose functions this emitter accepts.

const std = @import("std");
const ppc = @import("../ppc/root.zig");
const runtime = @import("../runtime/ctx.zig");
const abi = @import("abi.zig");

pub const Error = error{UnsupportedOpcode} || std.mem.Allocator.Error;

pub const Options = struct { addr: u32 };

const insn = ppc.decode.Instruction;

pub fn supports(op: insn) bool {
    return switch (op) {
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
        .lfs,
        .stfs,
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
        .blr,
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
        .b => |f| !f.absolute and !f.link,
        .bc => |f| !f.absolute and !f.link and runtime.Ctx.supportedBo(f.bo),
        .bclr => |f| !f.absolute and !f.link and runtime.Ctx.supportedBo(f.bo),
        .bl => |f| !f.absolute,
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
    var touches_ctx = false;
    for (words, 0..) |word, i| {
        const at = base + @as(u32, @intCast(i)) * 4;
        const op = ppc.decode.decode(word) catch return error.UnsupportedOpcode;
        switch (op) {
            .b => has_branch = true,
            .blr, .nop => {},
            .bc, .bclr => {
                has_branch = true;
                touches_ctx = true;
            },
            else => touches_ctx = true,
        }
        if (!supportsAt(op, at, base, end)) return error.UnsupportedOpcode;
    }

    var name_buf: [10]u8 = undefined;
    try out.print(allocator, "pub fn {s}(ctx: *Ctx) callconv(.c) void {{\n", .{
        abi.fnName(opts.addr, &name_buf),
    });
    if (!touches_ctx) try out.appendSlice(allocator, "    _ = ctx;\n");

    if (!has_branch) {
        for (words, 0..) |word, i| {
            const addr = base + @as(u32, @intCast(i)) * 4;
            try out.print(allocator, "    // 0x{X:0>8}\n", .{addr});
            const op = ppc.decode.decode(word) catch return error.UnsupportedOpcode;
            if (op == .blr) {
                try out.appendSlice(allocator, "    return;\n");
                break;
            }
            try lower(allocator, &out, op, addr);
        }
        try out.appendSlice(allocator, "}\n");
        return out.toOwnedSlice(allocator);
    }

    try out.print(allocator, "    var pc: u32 = 0x{X};\n", .{base});
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
                const target = addr +% f.target;
                if (inRange(target, base, end)) {
                    try out.print(allocator, "                pc = 0x{X};\n", .{target});
                } else {
                    try tailCall(allocator, &out, target);
                }
            },
            .bc => |f| {
                const target = addr +% f.target;
                if (inRange(target, base, end)) {
                    try out.print(allocator, "                pc = if (ctx.branch({d}, {d})) 0x{X} else 0x{X};\n", .{
                        f.bo, f.bi, target, next,
                    });
                } else {
                    try out.print(allocator, "                if (ctx.branch({d}, {d})) {{\n", .{ f.bo, f.bi });
                    try tailCall(allocator, &out, target);
                    try out.print(allocator, "                }}\n                pc = 0x{X};\n", .{next});
                }
            },
            .bclr => |f| try out.print(allocator, "                if (ctx.branch({d}, {d})) return;\n                pc = 0x{X};\n", .{
                f.bo, f.bi, next,
            }),
            else => {
                try lower(allocator, &out, op, addr);
                try out.print(allocator, "                pc = 0x{X};\n", .{next});
            },
        }
        try out.appendSlice(allocator, "            },\n");
    }

    try out.appendSlice(allocator, "            else => return,\n        }\n    }\n}\n");
    return out.toOwnedSlice(allocator);
}

fn tailCall(allocator: std.mem.Allocator, out: *std.ArrayList(u8), target: u32) !void {
    try out.print(allocator, "                if (!dispatch(0x{X}, ctx)) {{\n                    ctx.fault = .{{ .kind = .unsupported, .addr = 0x{X} }};\n                }}\n                return;\n", .{ target, target });
}

fn lower(allocator: std.mem.Allocator, out: *std.ArrayList(u8), op: insn, addr: u32) Error!void {
    switch (op) {
        .bl => |f| try out.print(allocator, "    ctx.lr = 0x{X};\n    if (!dispatch(0x{X}, ctx)) {{\n        ctx.fault = .{{ .kind = .unsupported, .addr = 0x{X} }};\n        return;\n    }}\n", .{
            addr +% 4, addr +% f.target, addr +% f.target,
        }),
        .nop => {},
        .addi => try immAdd(allocator, out, op.addi.rt, op.addi.ra, sext(op.addi.imm)),
        .addis => try immAdd(allocator, out, op.addis.rt, op.addis.ra, sext32(op.addis.imm)),
        .ori => try immU32(allocator, out, "|", op.ori.ra, op.ori.rt, op.ori.imm),
        .oris => try immU32Shifted(allocator, out, op.oris.ra, op.oris.rt, op.oris.imm),
        .andi_dot => {
            try immU32(allocator, out, "&", op.andi_dot.ra, op.andi_dot.rt, op.andi_dot.imm);
            try out.print(allocator, "    ctx.setCr(0, ctx.gpr[{d}], 0, true);\n", .{op.andi_dot.ra});
        },
        .or_ => try binop(allocator, out, "|", op.or_.ra, op.or_.rt, op.or_.rb),
        .add => try binop(allocator, out, "+%", op.add.rt, op.add.ra, op.add.rb),
        .subf => try subf(allocator, out, op.subf.rt, op.subf.ra, op.subf.rb),
        .mullw => try binop(allocator, out, "*%", op.mullw.rt, op.mullw.ra, op.mullw.rb),
        .sraw => try binop(allocator, out, "sraw", op.sraw.ra, op.sraw.rt, op.sraw.rb),
        .srawi => try out.print(allocator, "    ctx.gpr[{d}] = @as(u32, @bitCast(@as(i32, @truncate(@as(i64, @bitCast(ctx.gpr[{d}])))) >> {d}));\n", .{
            op.srawi.ra, op.srawi.rs, op.srawi.sh,
        }),
        .rlwinm => try out.print(allocator, "    ctx.gpr[{d}] = @as(u32, std.math.rotl(u32, @as(u32, @truncate(ctx.gpr[{d}])), {d})) & 0x{X:0>8};\n", .{
            op.rlwinm.ra, op.rlwinm.rs, op.rlwinm.sh, mask32(op.rlwinm.mb, op.rlwinm.me),
        }),
        .mflr => try mov(allocator, out, op.mflr.rt, "lr"),
        .mtlr => try movTo(allocator, out, "lr", op.mtlr.rt),
        .mfctr => try mov(allocator, out, op.mfctr.rt, "ctr"),
        .mtctr => try movTo(allocator, out, "ctr", op.mtctr.rt),
        .lwz => try load(allocator, out, op, 4, false),
        .lwzu => try load(allocator, out, op, 4, true),
        .lbz => try load(allocator, out, op, 1, false),
        .lbzu => try load(allocator, out, op, 1, true),
        .stw, .stb => try store(allocator, out, op, false),
        .stwu => try store(allocator, out, op, true),
        .lfs => try fLoad(allocator, out, op.lfs.frd, op.lfs.ra, op.lfs.imm),
        .stfs => try fStore(allocator, out, op.stfs.frd, op.stfs.ra, op.stfs.imm),
        .fadd => try fBinop(allocator, out, "+", op.fadd.frd, op.fadd.fra, op.fadd.frb),
        .fsub => try fBinop(allocator, out, "-", op.fsub.frd, op.fsub.fra, op.fsub.frb),
        .fmul => try fBinop(allocator, out, "*", op.fmul.frd, op.fmul.fra, op.fmul.frb),
        .fdiv => try fBinop(allocator, out, "/", op.fdiv.frd, op.fdiv.fra, op.fdiv.frb),
        .fcmpu => try out.print(allocator, "    ctx.setCrFloat({d}, ctx.fpr[{d}], ctx.fpr[{d}]);\n", .{
            op.fcmpu.crf, op.fcmpu.fra, op.fcmpu.frb,
        }),
        .cmpwi => try compareImm(allocator, out, op.cmpwi.crf, op.cmpwi.ra, op.cmpwi.imm, true),
        .cmplwi => try compareImm(allocator, out, op.cmplwi.crf, op.cmplwi.ra, op.cmplwi.imm, false),
        else => return error.UnsupportedOpcode,
    }
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
    if (std.mem.eql(u8, op, "sraw")) {
        try out.print(allocator, "    ctx.gpr[{d}] = @as(u32, @bitCast(@as(i32, @truncate(@as(i64, @bitCast(ctx.gpr[{d}])))) >> @as(u32, @truncate(ctx.gpr[{d}]))));\n", .{ gpr(rt), gpr(ra), gpr(rb) });
        return;
    }
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
        else => unreachable,
    };
    try printAddr(allocator, out, size * 8, "load", true, rt, ra, imm, update);
}

fn store(allocator: std.mem.Allocator, out: *std.ArrayList(u8), op: insn, update: bool) !void {
    const rt: u8, const ra: u8, const imm: i16, const size: u8 = switch (op) {
        .stw => |f| .{ f.rt, f.ra, f.imm, 32 },
        .stwu => |f| .{ f.rt, f.ra, f.imm, 32 },
        .stb => |f| .{ f.rt, f.ra, f.imm, 8 },
        else => unreachable,
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

fn compareImm(allocator: std.mem.Allocator, out: *std.ArrayList(u8), crf: u3, ra: u8, imm: anytype, signed: bool) !void {
    try out.print(allocator, "    ctx.setCr({d}, ctx.gpr[{d}], 0x{X:0>16}, {s});\n", .{
        crf, gpr(ra), @as(u64, @bitCast(@as(i64, imm))), if (signed) "true" else "false",
    });
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

test "golden function" {
    const words = [_]u32{ 0x38600001, 0x914b0014, 0x4e800020 };
    const text = try function(testing.allocator, &words, .{ .addr = 0x100 });
    defer testing.allocator.free(text);

    try testing.expectEqualStrings(
        \\pub fn g_00000100(ctx: *Ctx) callconv(.c) void {
        \\    // 0x00000100
        \\    ctx.gpr[3] = 0x0000000000000001;
        \\    // 0x00000104
        \\    ctx.store32(@as(u32, @truncate(ctx.gpr[11])) +% 0x00000014, ctx.gpr[10]);
        \\    // 0x00000108
        \\    return;
        \\}
        \\
    , text);
}

test "vmx is refused" {
    const words = [_]u32{ 0x10221cc4, 0x4e800020 };
    try testing.expectError(error.UnsupportedOpcode, function(testing.allocator, &words, .{ .addr = 0 }));
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
