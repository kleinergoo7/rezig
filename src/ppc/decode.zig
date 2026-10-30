//! PowerPC (Xenon) instruction decode for the P0 subset.
//!
//! Every encoding here was assembled with `zig build-obj -target powerpc64-linux-gnu` and
//! checked with `llvm-objdump` before being written down.

const std = @import("std");

pub const Error = error{Unsupported};

pub const DForm = struct { rt: u8, ra: u8, imm: i16 };
pub const UForm = struct { rt: u8, ra: u8, imm: u16 };
pub const CmpForm = struct { crf: u3, ra: u8, imm: i16 };
pub const CmpLForm = struct { crf: u3, ra: u8, imm: u16 };
pub const CmpXForm = struct { crf: u3, ra: u8, rb: u8 };
pub const DSForm = struct { rt: u8, ra: u8, ds: i16 };
pub const XForm = struct { rt: u8, ra: u8, rb: u8 };
pub const ShiftForm = struct { ra: u8, rs: u8, sh: u5 };
pub const RotForm = struct { ra: u8, rs: u8, sh: u5, mb: u5, me: u5 };
pub const BranchForm = struct { target: u32, absolute: bool, link: bool };
pub const BcForm = struct { bo: u5, bi: u5, target: u32, absolute: bool, link: bool };
pub const SprForm = struct { rt: u8 };
pub const FForm = struct { frd: u8, fra: u8, frb: u8 };
pub const FCmpForm = struct { crf: u3, fra: u8, frb: u8 };
pub const FdForm = struct { frd: u8, ra: u8, imm: i16 };
/// VMX three-register form; `va` is the second source.
pub const VForm = struct { vd: u8, va: u8, vb: u8 };
/// VMX load/store form.
pub const VMemForm = struct { vd: u8, ra: u8, rb: u8 };

pub const Instruction = union(enum) {
    addi: DForm,
    addis: DForm,
    lwz: DForm,
    lwzu: DForm,
    stw: DForm,
    stwu: DForm,
    lbz: DForm,
    lbzu: DForm,
    stb: DForm,
    lfs: FdForm,
    stfs: FdForm,
    ori: UForm,
    oris: UForm,
    andi_dot: UForm,
    cmpwi: CmpForm,
    cmplwi: CmpLForm,
    cmpw: CmpXForm,
    cmplw: CmpXForm,
    ld: DSForm,
    ldu: DSForm,
    lwa: DSForm,
    std: DSForm,
    stdu: DSForm,
    lwzx: XForm,
    lbzx: XForm,
    stwx: XForm,
    mulli: DForm,
    extsh: XForm,
    extsb: XForm,
    extsw: XForm,
    or_: XForm,
    add: XForm,
    subf: XForm,
    mullw: XForm,
    sraw: XForm,
    srawi: ShiftForm,
    rlwinm: RotForm,
    b: BranchForm,
    bl: BranchForm,
    bc: BcForm,
    bclr: BcForm,
    blr,
    nop,
    mflr: SprForm,
    mtlr: SprForm,
    mfctr: SprForm,
    mtctr: SprForm,
    fadd: FForm,
    fsub: FForm,
    fmul: FForm,
    fdiv: FForm,
    fcmpu: FCmpForm,
    fmr: FForm,
    fadds: FForm,
    fsubs: FForm,
    fmuls: FForm,
    fdivs: FForm,
    fctiwz: FForm,
    lfd: FdForm,
    stfd: FdForm,
    lvx: VMemForm,
    stvx: VMemForm,
    vxor: VForm,
    vaddfp: VForm,
    vor: VForm,
};

pub fn decode(word: u32) Error!Instruction {
    if (word == 0x60000000) return .nop;
    const op = word >> 26;
    return switch (op) {
        7 => .{ .mulli = dForm(word) },
        14 => .{ .addi = dForm(word) },
        15 => .{ .addis = dForm(word) },
        24 => .{ .ori = uForm(word) },
        25 => .{ .oris = uForm(word) },
        28 => .{ .andi_dot = uForm(word) },
        32 => .{ .lwz = dForm(word) },
        33 => .{ .lwzu = dForm(word) },
        36 => .{ .stw = dForm(word) },
        37 => .{ .stwu = dForm(word) },
        34 => .{ .lbz = dForm(word) },
        35 => .{ .lbzu = dForm(word) },
        38 => .{ .stb = dForm(word) },
        48 => .{ .lfs = fdForm(word) },
        50 => .{ .lfd = fdForm(word) },
        52 => .{ .stfs = fdForm(word) },
        54 => .{ .stfd = fdForm(word) },
        59 => try decodeAForm(word, 59),
        58 => switch (word & 0x3) {
            0 => .{ .ld = dsForm(word) },
            1 => .{ .ldu = dsForm(word) },
            2 => .{ .lwa = dsForm(word) },
            else => error.Unsupported,
        },
        11 => .{ .cmpwi = .{ .crf = crf(word), .ra = ra(word), .imm = @bitCast(@as(u16, @truncate(word))) } },
        10 => .{ .cmplwi = .{ .crf = crf(word), .ra = ra(word), .imm = @truncate(word) } },
        21 => .{ .rlwinm = .{
            .ra = ra(word),
            .rs = rt(word),
            .sh = @truncate((word >> 11) & 0x1f),
            .mb = @truncate((word >> 6) & 0x1f),
            .me = @truncate((word >> 1) & 0x1f),
        } },
        18 => if (word & 1 != 0) .{ .bl = branchForm(word) } else .{ .b = branchForm(word) },
        16 => .{ .bc = bcForm(word) },
        19 => switch (xo10(word)) {
            16, 528 => if (bo(word) == 20 and bi(word) == 0 and word & 1 == 0)
                .blr
            else
                .{ .bclr = bcForm(word) },
            else => error.Unsupported,
        },
        31 => try decodeXForm(word),
        62 => switch (word & 0x3) {
            0 => .{ .std = dsForm(word) },
            1 => .{ .stdu = dsForm(word) },
            else => error.Unsupported,
        },
        63 => try decodeAForm(word, 63),
        4 => try decodeVForm(word),
        else => error.Unsupported,
    };
}

pub fn isBranchToLink(insn: Instruction) ?u32 {
    return switch (insn) {
        .bl => |b| b.target,
        else => null,
    };
}

pub fn isReturn(insn: Instruction) bool {
    return insn == .blr;
}

pub fn isBranch(insn: Instruction) bool {
    return switch (insn) {
        .b, .bl, .bc, .bclr, .blr => true,
        else => false,
    };
}

fn decodeXForm(word: u32) Error!Instruction {
    const xo = xo10(word);
    if (word == 0x60000000) return .nop;
    return switch (xo) {
        444 => .{ .or_ = xForm(word) },
        266 => .{ .add = xForm(word) },
        40 => .{ .subf = xForm(word) },
        235 => .{ .mullw = xForm(word) },
        0 => if (lBit(word) == 0) .{ .cmpw = .{ .crf = crf(word), .ra = ra(word), .rb = rb(word) } } else error.Unsupported,
        23 => .{ .lwzx = xForm(word) },
        32 => if (lBit(word) == 0) .{ .cmplw = .{ .crf = crf(word), .ra = ra(word), .rb = rb(word) } } else error.Unsupported,
        87 => .{ .lbzx = xForm(word) },
        151 => .{ .stwx = xForm(word) },
        792 => .{ .sraw = xForm(word) },
        922 => .{ .extsh = .{ .rt = rt(word), .ra = ra(word), .rb = 0 } },
        954 => .{ .extsb = .{ .rt = rt(word), .ra = ra(word), .rb = 0 } },
        986 => .{ .extsw = .{ .rt = rt(word), .ra = ra(word), .rb = 0 } },
        824 => .{ .srawi = .{
            .ra = ra(word),
            .rs = rt(word),
            .sh = @truncate((word >> 11) & 0x1f),
        } },
        339 => .{ .mflr = .{ .rt = rt(word) } },
        467 => .{ .mtlr = .{ .rt = rt(word) } },
        19 => .{ .mfctr = .{ .rt = rt(word) } },
        51 => .{ .mtctr = .{ .rt = rt(word) } },
        103 => .{ .lvx = vMemForm(word) },
        231 => .{ .stvx = vMemForm(word) },
        else => error.Unsupported,
    };
}

fn decodeAForm(word: u32, primary: u8) Error!Instruction {
    const xo = (word >> 1) & 0x1f;
    if (primary == 59) {
        return switch (xo) {
            21 => .{ .fadds = fForm(word) },
            20 => .{ .fsubs = fForm(word) },
            25 => .{ .fmuls = fForm(word) },
            18 => .{ .fdivs = fForm(word) },
            else => error.Unsupported,
        };
    }
    return switch (xo) {
        21 => .{ .fadd = fForm(word) },
        20 => .{ .fsub = fForm(word) },
        25 => .{ .fmul = fForm(word) },
        18 => .{ .fdiv = fForm(word) },
        0 => .{ .fcmpu = .{ .crf = crf(word), .fra = fra(word), .frb = frb(word) } },
        72 => .{ .fmr = fForm(word) },
        15 => .{ .fctiwz = fForm(word) },
        else => error.Unsupported,
    };
}

fn decodeVForm(word: u32) Error!Instruction {
    const xo = word & 0x7ff;
    return switch (xo) {
        1220 => .{ .vxor = .{ .vd = rt(word), .va = ra(word), .vb = rb(word) } },
        10 => .{ .vaddfp = .{ .vd = rt(word), .va = ra(word), .vb = rb(word) } },
        1156 => .{ .vor = .{ .vd = rt(word), .va = ra(word), .vb = rb(word) } },
        else => error.Unsupported,
    };
}

fn rt(word: u32) u8 {
    return @truncate((word >> 21) & 0x1f);
}

fn ra(word: u32) u8 {
    return @truncate((word >> 16) & 0x1f);
}

fn rb(word: u32) u8 {
    return @truncate((word >> 11) & 0x1f);
}

fn crf(word: u32) u3 {
    return @truncate((word >> 23) & 0x7);
}

fn bo(word: u32) u5 {
    return @truncate((word >> 21) & 0x1f);
}

fn lBit(word: u32) u1 {
    return @truncate((word >> 21) & 0x1);
}

fn dsForm(word: u32) DSForm {
    const raw: i32 = @as(i32, @bitCast(word & 0xFFFC)) >> 2;
    const ds: i16 = if (raw & 0x2000 != 0) @intCast(raw - 0x4000) else @intCast(raw);
    return .{ .rt = rt(word), .ra = ra(word), .ds = ds };
}

fn bi(word: u32) u5 {
    return @truncate((word >> 16) & 0x1f);
}

fn xo10(word: u32) u16 {
    return @truncate((word >> 1) & 0x3ff);
}

fn fra(word: u32) u8 {
    return @truncate((word >> 16) & 0x1f);
}

fn frb(word: u32) u8 {
    return @truncate((word >> 11) & 0x1f);
}

fn dForm(word: u32) DForm {
    return .{
        .rt = rt(word),
        .ra = ra(word),
        .imm = @bitCast(@as(u16, @truncate(word))),
    };
}

fn uForm(word: u32) UForm {
    return .{ .rt = rt(word), .ra = ra(word), .imm = @truncate(word) };
}

fn fdForm(word: u32) FdForm {
    return .{ .frd = rt(word), .ra = ra(word), .imm = @bitCast(@as(u16, @truncate(word))) };
}

fn xForm(word: u32) XForm {
    return .{ .rt = rt(word), .ra = ra(word), .rb = rb(word) };
}

fn fForm(word: u32) FForm {
    return .{ .frd = rt(word), .fra = fra(word), .frb = frb(word) };
}

fn vMemForm(word: u32) VMemForm {
    return .{ .vd = rt(word), .ra = ra(word), .rb = rb(word) };
}

fn branchForm(word: u32) BranchForm {
    const offset = @as(i32, @bitCast((word & 0x03ff_fffc) << 6)) >> 6;
    return .{
        .target = @bitCast(offset),
        .absolute = word & 2 != 0,
        .link = word & 1 != 0,
    };
}

fn bcForm(word: u32) BcForm {
    const offset = @as(i32, @bitCast((word & 0x0000_fffc) << 16)) >> 16;
    return .{
        .bo = bo(word),
        .bi = bi(word),
        .target = @bitCast(offset),
        .absolute = word & 2 != 0,
        .link = word & 1 != 0,
    };
}

const testing = std.testing;

fn expectDecode(word: u32, expected: Instruction) !void {
    const got = try decode(word);
    try testing.expectEqual(std.meta.activeTag(expected), std.meta.activeTag(got));
    try testing.expectEqualDeep(expected, got);
}

test "d-form instructions decode to verified operands" {
    try expectDecode(0x38600001, .{ .addi = .{ .rt = 3, .ra = 0, .imm = 1 } });
    try expectDecode(0x3c851234, .{ .addis = .{ .rt = 4, .ra = 5, .imm = 0x1234 } });
    try expectDecode(0x60c6abcd, .{ .ori = .{ .rt = 6, .ra = 6, .imm = 0xabcd } });
    try expectDecode(0x81090010, .{ .lwz = .{ .rt = 8, .ra = 9, .imm = 16 } });
    try expectDecode(0x914b0014, .{ .stw = .{ .rt = 10, .ra = 11, .imm = 20 } });
    try expectDecode(0x898d0003, .{ .lbz = .{ .rt = 12, .ra = 13, .imm = 3 } });
    try expectDecode(0x99cf0004, .{ .stb = .{ .rt = 14, .ra = 15, .imm = 4 } });
    try expectDecode(0xc1f10010, .{ .lfs = .{ .frd = 15, .ra = 17, .imm = 16 } });
}

test "compare and logical immediates decode" {
    try expectDecode(0x2c100005, .{ .cmpwi = .{ .crf = 0, .ra = 16, .imm = 5 } });
    try expectDecode(0x28910007, .{ .cmplwi = .{ .crf = 1, .ra = 17, .imm = 7 } });
    try expectDecode(0x727200ff, .{ .andi_dot = .{ .rt = 19, .ra = 18, .imm = 0xff } });
}

test "x-form, shift and rotate decode" {
    try expectDecode(0x7eb4b378, .{ .or_ = .{ .rt = 21, .ra = 20, .rb = 22 } });
    try expectDecode(0x7ef8ca14, .{ .add = .{ .rt = 23, .ra = 24, .rb = 25 } });
    try expectDecode(0x7f5be050, .{ .subf = .{ .rt = 26, .ra = 27, .rb = 28 } });
    try expectDecode(0x7fbef9d6, .{ .mullw = .{ .rt = 29, .ra = 30, .rb = 31 } });
    try expectDecode(0x7c832e70, .{ .srawi = .{ .ra = 3, .rs = 4, .sh = 5 } });
    try expectDecode(0x55495b1a, .{ .rlwinm = .{ .ra = 9, .rs = 10, .sh = 11, .mb = 12, .me = 13 } });
    try expectDecode(0x7ca802a6, .{ .mflr = .{ .rt = 5 } });
    try expectDecode(0x60000000, .nop);
}

test "float and vmx decode" {
    try expectDecode(0xfc22182a, .{ .fadd = .{ .frd = 1, .fra = 2, .frb = 3 } });
    try expectDecode(0xfc0d7000, .{ .fcmpu = .{ .crf = 0, .fra = 13, .frb = 14 } });
    try expectDecode(0x10221cc4, .{ .vxor = .{ .vd = 1, .va = 2, .vb = 3 } });
    try expectDecode(0x10e84c84, .{ .vor = .{ .vd = 7, .va = 8, .vb = 9 } });
    try expectDecode(0x7d4b60ce, .{ .lvx = .{ .vd = 10, .ra = 11, .rb = 12 } });
    try expectDecode(0x7dae79ce, .{ .stvx = .{ .vd = 13, .ra = 14, .rb = 15 } });
}

test "blr is a return and bl is a call" {
    try expectDecode(0x4e800020, .blr);
    try testing.expect(isReturn(.blr));
    try testing.expectEqual(@as(?u32, 0x2000), isBranchToLink(try decode(0x48002001)));
    try testing.expectEqual(@as(?u32, null), isBranchToLink(try decode(0x48002000)));
}

test "unknown words are refused" {
    try testing.expectError(error.Unsupported, decode(0x00000000));
}
