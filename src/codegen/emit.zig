//! Zig emitter for the P0 integer subset.
//!
//! Branches inside a function, float and VMX instructions are refused by name; the slice
//! selector must only choose functions this emitter accepts.

const std = @import("std");
const ppc = @import("../ppc/root.zig");
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

pub fn function(allocator: std.mem.Allocator, words: []const u32, opts: Options) Error![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    var name_buf: [10]u8 = undefined;
    var addr_buf: [10]u8 = undefined;
    try out.print(allocator, "pub fn {s}(ctx: *Ctx) callconv(.c) void {{\n", .{
        abi.fnName(opts.addr, &name_buf),
    });

    for (words, 0..) |word, i| {
        const addr = opts.addr + @as(u32, @intCast(i)) * 4;
        try out.print(allocator, "    // 0x{s}\n", .{abi.fnName(addr, &addr_buf)[2..]});

        const op = ppc.decode.decode(word) catch return error.UnsupportedOpcode;
        if (!supports(op)) return error.UnsupportedOpcode;

        switch (op) {
            .blr => try out.appendSlice(allocator, "    return;\n"),
            .nop => {},
            .addi => try imm32(allocator, &out, "add", op.addi.rt, op.addi.ra, op.addi.imm),
            .addis => try imm32(allocator, &out, "shl_add", op.addis.rt, op.addis.ra, op.addis.imm),
            .ori => try immU32(allocator, &out, "|", op.ori.rt, op.ori.ra, op.ori.imm),
            .oris => try immU32Shifted(allocator, &out, op.oris.rt, op.oris.ra, op.oris.imm),
            .andi_dot => {
                try immU32(allocator, &out, "&", op.andi_dot.rt, op.andi_dot.ra, op.andi_dot.imm);
                try out.print(allocator, "    ctx.setCr(0, ctx.gpr[{d}], 0, true);\n", .{op.andi_dot.rt});
            },
            .or_ => try binop(allocator, &out, "|", op.or_.rt, op.or_.ra, op.or_.rb),
            .add => try binop(allocator, &out, "+%", op.add.rt, op.add.ra, op.add.rb),
            .subf => try subf(allocator, &out, op.subf.rt, op.subf.ra, op.subf.rb),
            .mullw => try binop(allocator, &out, "*%", op.mullw.rt, op.mullw.ra, op.mullw.rb),
            .sraw => try binop(allocator, &out, "sraw", op.sraw.rt, op.sraw.ra, op.sraw.rb),
            .srawi => try out.print(allocator, "    ctx.gpr[{d}] = @as(u32, @bitCast(@as(i32, @truncate(@as(i64, @bitCast(ctx.gpr[{d}])))) >> {d}));\n", .{
                op.srawi.ra, op.srawi.rs, op.srawi.sh,
            }),
            .rlwinm => try out.print(allocator, "    ctx.gpr[{d}] = @as(u32, std.math.rotl(u32, @truncate(ctx.gpr[{d}]), {d})) & 0x{X:0>8};\n", .{
                op.rlwinm.ra, op.rlwinm.rs, op.rlwinm.sh, mask32(op.rlwinm.mb, op.rlwinm.me),
            }),
            .mflr => try mov(allocator, &out, op.mflr.rt, "lr"),
            .mtlr => try movTo(allocator, &out, "lr", op.mtlr.rt),
            .mfctr => try mov(allocator, &out, op.mfctr.rt, "ctr"),
            .mtctr => try movTo(allocator, &out, "ctr", op.mtctr.rt),
            .lwz, .lbz => try load(allocator, &out, op, 4),
            .lbzu => try load(allocator, &out, op, 1),
            .lwzu => try load(allocator, &out, op, 4),
            .stw, .stb, .stwu => try store(allocator, &out, op),
            .cmpwi => try compareImm(allocator, &out, op.cmpwi.crf, op.cmpwi.ra, op.cmpwi.imm, true),
            .cmplwi => try compareImm(allocator, &out, op.cmplwi.crf, op.cmplwi.ra, op.cmplwi.imm, false),
            else => return error.UnsupportedOpcode,
        }
    }

    try out.appendSlice(allocator, "}\n");
    return out.toOwnedSlice(allocator);
}

fn gpr(reg: u8) u8 {
    return reg;
}

fn imm32(allocator: std.mem.Allocator, out: *std.ArrayList(u8), comptime op: []const u8, rt: u8, ra: u8, imm: i16) !void {
    if (std.mem.eql(u8, op, "add")) {
        if (ra == 0) {
            try out.print(allocator, "    ctx.gpr[{d}] = 0x{X:0>16};\n", .{ gpr(rt), @as(u64, @bitCast(@as(i64, imm))) & 0xffff_ffff });
        } else {
            try out.print(allocator, "    ctx.gpr[{d}] = ctx.gpr[{d}] +% 0x{X};\n", .{ gpr(rt), gpr(ra), @as(u64, @bitCast(@as(i64, imm))) & 0xffff_ffff });
        }
    } else {
        try out.print(allocator, "    ctx.gpr[{d}] = (ctx.gpr[{d}] << 16) +% 0x{X:0>16};\n", .{ gpr(rt), gpr(ra), @as(u64, @bitCast(@as(i64, imm))) & 0xffff_ffff });
    }
}

fn immU32(allocator: std.mem.Allocator, out: *std.ArrayList(u8), comptime op: []const u8, rt: u8, ra: u8, imm: u16) !void {
    try out.print(allocator, "    ctx.gpr[{d}] = ctx.gpr[{d}] {s} 0x{X};\n", .{ gpr(rt), gpr(ra), op, imm });
}

fn immU32Shifted(allocator: std.mem.Allocator, out: *std.ArrayList(u8), rt: u8, ra: u8, imm: u16) !void {
    try out.print(allocator, "    ctx.gpr[{d}] = ctx.gpr[{d}] | 0x{X:0>8};\n", .{ gpr(rt), gpr(ra), @as(u32, imm) << 16 });
}

fn binop(allocator: std.mem.Allocator, out: *std.ArrayList(u8), comptime op: []const u8, rt: u8, ra: u8, rb: u8) !void {
    if (std.mem.eql(u8, op, "sraw")) {
        try out.print(allocator, "    ctx.gpr[{d}] = @as(u32, @bitCast(@as(i32, @truncate(@as(i64, @bitCast(ctx.gpr[{d}])))) >> @truncate(ctx.gpr[{d}])));\n", .{ gpr(rt), gpr(ra), gpr(rb) });
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
    try out.print(allocator, "    ctx.{s} = ctx.gpr[{d}];\n", .{ field, gpr(rt) });
}

fn load(allocator: std.mem.Allocator, out: *std.ArrayList(u8), op: insn, comptime size: u8) !void {
    const rt, const ra, const imm = switch (op) {
        .lwz => |f| .{ f.rt, f.ra, f.imm },
        .lwzu => |f| .{ f.rt, f.ra, f.imm },
        .lbz => |f| .{ f.rt, f.ra, f.imm },
        .lbzu => |f| .{ f.rt, f.ra, f.imm },
        else => unreachable,
    };
    try out.print(allocator, "    ctx.gpr[{d}] = ctx.load{d}(ctx.gpr[{d}] +% 0x{X});\n", .{ gpr(rt), size * 8, gpr(ra), @as(u16, @bitCast(imm)) });
}

fn store(allocator: std.mem.Allocator, out: *std.ArrayList(u8), op: insn) !void {
    const rt: u8, const ra: u8, const imm: i16, const size: u8 = switch (op) {
        .stw => |f| .{ f.rt, f.ra, f.imm, 32 },
        .stwu => |f| .{ f.rt, f.ra, f.imm, 32 },
        .stb => |f| .{ f.rt, f.ra, f.imm, 8 },
        else => unreachable,
    };
    try out.print(allocator, "    ctx.store{d}(ctx.gpr[{d}] +% 0x{X}, ctx.gpr[{d}]);\n", .{ size, gpr(ra), @as(u16, @bitCast(imm)), gpr(rt) });
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
        \\    ctx.store32(ctx.gpr[11] +% 0x14, ctx.gpr[10]);
        \\    // 0x00000108
        \\    return;
        \\}
        \\
    , text);
}

test "float and vmx are refused" {
    const words = [_]u32{ 0xfc22182a, 0x4e800020 };
    try testing.expectError(error.UnsupportedOpcode, function(testing.allocator, &words, .{ .addr = 0 }));
}

test "a branch inside a function is refused" {
    const words = [_]u32{ 0x48000001, 0x4e800020 };
    try testing.expectError(error.UnsupportedOpcode, function(testing.allocator, &words, .{ .addr = 0 }));
}
