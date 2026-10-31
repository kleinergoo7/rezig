//! PowerPC (Xenon) instruction decode for the P0 subset.
//!
//! Every encoding here was assembled with `zig build-obj -target powerpc64-linux-gnu` and
//! checked with `llvm-objdump` before being written down.

const std = @import("std");

pub const Error = error{Unsupported};

pub const DForm = struct { rt: u8, ra: u8, imm: i16 };
pub const AddicForm = struct { rt: u8, ra: u8, imm: i16, rc: bool = false };
pub const UForm = struct { rt: u8, ra: u8, imm: u16 };
pub const CmpForm = struct { crf: u3, ra: u8, imm: i16 };
pub const CmpLForm = struct { crf: u3, ra: u8, imm: u16 };
pub const CmpXForm = struct { crf: u3, ra: u8, rb: u8 };
pub const DSForm = struct { rt: u8, ra: u8, ds: i16 };
pub const XForm = struct { rt: u8, ra: u8, rb: u8, rc: bool = false };
pub const ShiftForm = struct { ra: u8, rs: u8, sh: u6, rc: bool = false };
pub const RotForm = struct { ra: u8, rs: u8, sh: u5, mb: u5, me: u5, rc: bool = false };
pub const RlwnmForm = struct { ra: u8, rs: u8, rb: u8, mb: u5, me: u5, rc: bool = false };
pub const RldicrForm = struct { ra: u8, rs: u8, sh: u6, me: u6, rc: bool = false };
pub const BranchForm = struct { target: u32, absolute: bool, link: bool };
pub const BcForm = struct { bo: u5, bi: u5, target: u32, absolute: bool, link: bool, to_ctr: bool = false };
pub const SprForm = struct { rt: u8, spr: u10 = 0 };
pub const OcrfForm = struct { rt: u8, crm: u8 };
pub const TwiForm = struct { to: u5, ra: u8, imm: i16 };
pub const TwForm = struct { to: u5, ra: u8, rb: u8 };
pub const CrKind = enum { crand, crandc, creqv, crnand, crnor, cror, crorc, crxor };
pub const CrOpForm = struct { kind: CrKind, bt: u5, ba: u5, bb: u5 };
pub const McrfForm = struct { crf_d: u3, crf_s: u3 };
pub const FForm = struct { frd: u8, fra: u8, frb: u8, rc: bool = false };
pub const FCmpForm = struct { crf: u3, fra: u8, frb: u8 };
pub const FdForm = struct { frd: u8, ra: u8, imm: i16 };
pub const FMForm = struct { frd: u8, fra: u8, frc: u8, frb: u8, rc: bool = false };
/// VMX three-register form; `va` is the second source.
pub const VForm = struct { vd: u8, va: u8, vb: u8 };
/// VMX load/store form.
pub const VMemForm = struct { vd: u8, ra: u8, rb: u8 };
pub const VPermForm = struct { vd: u8, va: u8, vb: u8, vc: u8 };
pub const VmaddForm = struct { vd: u8, va: u8, vc: u8, vb: u8 };
pub const VSplatForm = struct { vd: u8, simm: i5 };

pub const Instruction = union(enum) {
    addi: DForm,
    addis: DForm,
    addic: AddicForm,
    twi: TwiForm,
    tw: TwForm,
    andis_dot: UForm,
    cr_op: CrOpForm,
    mcrf: McrfForm,
    rfid,
    lwz: DForm,
    lwzu: DForm,
    stw: DForm,
    stwu: DForm,
    lbz: DForm,
    lbzu: DForm,
    stb: DForm,
    sth: DForm,
    lfs: FdForm,
    lfsu: FdForm,
    stfs: FdForm,
    stfsu: FdForm,
    lfdu: FdForm,
    stfdu: FdForm,
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
    stbx: XForm,
    lfsx: FForm,
    cntlzw: XForm,
    mulli: DForm,
    extsh: XForm,
    extsb: XForm,
    extsw: XForm,
    or_: XForm,
    and_: XForm,
    xori: UForm,
    xoris: UForm,
    subfic: DForm,
    rldicr: RldicrForm,
    stfiwx: XForm,
    add: XForm,
    addc: XForm,
    adde: XForm,
    addze: XForm,
    subf: XForm,
    subfc: XForm,
    subfe: XForm,
    subfme: XForm,
    subfze: XForm,
    neg: XForm,
    mullw: XForm,
    mulhw: XForm,
    mulhwu: XForm,
    mulld: XForm,
    divw: XForm,
    divwu: XForm,
    divdu: XForm,
    slw: XForm,
    srw: XForm,
    sld: XForm,
    srd: XForm,
    sradi: ShiftForm,
    xor_: XForm,
    andc: XForm,
    eqv: XForm,
    nor_: XForm,
    cmpd: CmpXForm,
    cmpld: CmpXForm,
    sraw: XForm,
    srawi: ShiftForm,
    rlwinm: RotForm,
    rlwnm: RlwnmForm,
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
    mfspr: SprForm,
    mtspr: SprForm,
    mfmsr: SprForm,
    mtmsr: SprForm,
    mtmsrd: SprForm,
    mtocrf: OcrfForm,
    mfocrf: OcrfForm,
    lwsync,
    sync,
    isync,
    eieio,
    dcbt: XForm,
    dcbf: XForm,
    dcbst: XForm,
    dcbz: XForm,
    icbi: XForm,
    lwarx: XForm,
    stwcx: XForm,
    lhzu: DForm,
    lha: DForm,
    lhau: DForm,
    stbu: DForm,
    sthu: DForm,
    stbux: XForm,
    sthx: XForm,
    ldx: XForm,
    stdx: XForm,
    lwzux: XForm,
    stwux: XForm,
    lbzux: XForm,
    lwbrx: XForm,
    lhbrx: XForm,
    lhax: XForm,
    lhaux: XForm,
    stwbrx: XForm,
    sthbrx: XForm,
    lfdx: FForm,
    stfsx: FForm,
    stfdx: FForm,
    fadd: FForm,
    fsub: FForm,
    fmul: FForm,
    fdiv: FForm,
    fcmpu: FCmpForm,
    fmr: FForm,
    frsp: FForm,
    fneg: FForm,
    fabs: FForm,
    fcfid: FForm,
    fadds: FForm,
    fsubs: FForm,
    fmuls: FForm,
    fdivs: FForm,
    fsqrts: FForm,
    fctiwz: FForm,
    fctidz: FForm,
    fmadds: FMForm,
    fmsubs: FMForm,
    fnmsubs: FMForm,
    fnmadds: FMForm,
    fmadd: FMForm,
    fmsub: FMForm,
    fnmsub: FMForm,
    fnmadd: FMForm,
    lhz: DForm,
    rlwimi: RotForm,
    lfd: FdForm,
    stfd: FdForm,
    lvx: VMemForm,
    stvx: VMemForm,
    vxor: VForm,
    vaddfp: VForm,
    vor: VForm,
    vcmpequb: VForm,
    vcmpgtub: VForm,
    vand: VForm,
    vsubfp: VForm,
    vrlw: VForm,
    vperm: VPermForm,
    vmaddfp: VmaddForm,
    vspltisw: VSplatForm,
};

pub fn decode(word: u32) Error!Instruction {
    if (word == 0x60000000) return .nop;
    const op = word >> 26;
    return switch (op) {
        3 => .{ .twi = .{ .to = @truncate((word >> 21) & 0x1f), .ra = ra(word), .imm = @bitCast(@as(u16, @truncate(word))) } },
        6 => .{ .cmpwi = .{ .crf = crf(word), .ra = ra(word), .imm = @bitCast(@as(u16, @truncate(word))) } },
        7 => .{ .mulli = dForm(word) },
        12 => .{ .addic = addicForm(word, false) },
        13 => .{ .addic = addicForm(word, true) },
        8 => .{ .subfic = dForm(word) },
        14 => .{ .addi = dForm(word) },
        15 => .{ .addis = dForm(word) },
        24 => .{ .ori = uForm(word) },
        25 => .{ .oris = uForm(word) },
        26 => .{ .xori = uForm(word) },
        27 => .{ .xoris = uForm(word) },
        28 => .{ .andi_dot = uForm(word) },
        29 => .{ .andis_dot = uForm(word) },
        32 => .{ .lwz = dForm(word) },
        33 => .{ .lwzu = dForm(word) },
        36 => .{ .stw = dForm(word) },
        37 => .{ .stwu = dForm(word) },
        34 => .{ .lbz = dForm(word) },
        35 => .{ .lbzu = dForm(word) },
        38 => .{ .stb = dForm(word) },
        39 => .{ .stbu = dForm(word) },
        40 => .{ .lhz = dForm(word) },
        41 => .{ .lhzu = dForm(word) },
        42 => .{ .lha = dForm(word) },
        43 => .{ .lhau = dForm(word) },
        44 => .{ .sth = dForm(word) },
        45 => .{ .sthu = dForm(word) },
        48 => .{ .lfs = fdForm(word) },
        49 => .{ .lfsu = fdForm(word) },
        50 => .{ .lfd = fdForm(word) },
        51 => .{ .lfdu = fdForm(word) },
        52 => .{ .stfs = fdForm(word) },
        53 => .{ .stfsu = fdForm(word) },
        54 => .{ .stfd = fdForm(word) },
        55 => .{ .stfdu = fdForm(word) },
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
            .rc = word & 1 != 0,
        } },
        18 => if (word & 1 != 0) .{ .bl = branchForm(word) } else .{ .b = branchForm(word) },
        23 => .{ .rlwnm = .{
            .ra = ra(word),
            .rs = rt(word),
            .rb = rb(word),
            .mb = @truncate((word >> 6) & 0x1f),
            .me = @truncate((word >> 1) & 0x1f),
            .rc = word & 1 != 0,
        } },
        20 => .{ .rlwimi = .{
            .ra = ra(word),
            .rs = rt(word),
            .sh = @truncate((word >> 11) & 0x1f),
            .mb = @truncate((word >> 6) & 0x1f),
            .me = @truncate((word >> 1) & 0x1f),
            .rc = word & 1 != 0,
        } },
        16 => .{ .bc = bcForm(word) },
        19 => switch (xo10(word)) {
            0 => .{ .mcrf = .{ .crf_d = crf(word), .crf_s = @truncate((word >> 18) & 0x7) } },
            18 => .rfid,
            33 => crOp(.crnor, word),
            129 => crOp(.crandc, word),
            150 => .isync,
            193 => crOp(.crxor, word),
            225 => crOp(.crnand, word),
            257 => crOp(.crand, word),
            289 => crOp(.creqv, word),
            417 => crOp(.crorc, word),
            449 => crOp(.cror, word),
            16 => if (bo(word) == 20 and bi(word) == 0 and word & 1 == 0)
                .blr
            else
                .{ .bclr = bclrForm(word) },
            528 => blk: {
                var f = bclrForm(word);
                f.to_ctr = true;
                break :blk .{ .bclr = f };
            },
            else => error.Unsupported,
        },
        30 => .{
            .rldicr = .{
                .ra = ra(word),
                .rs = rt(word),
                // MD-form: SH bit 5 is at bit 30, ME bit 5 at bit 26.
                .sh = @intCast(((word >> 11) & 0x1f) | (((word >> 1) & 1) << 5)),
                .me = @intCast(((word >> 6) & 0x1f) | (((word >> 5) & 1) << 5)),
                .rc = word & 1 != 0,
            },
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
    if ((word >> 2) & 0x1ff == 413) {
        return .{ .sradi = .{
            .ra = ra(word),
            .rs = rt(word),
            .sh = @intCast(((word >> 11) & 0x1f) | (((word >> 1) & 1) << 5)),
            .rc = word & 1 != 0,
        } };
    }
    const xo = xo10(word);
    if (word == 0x60000000) return .nop;
    return switch (xo) {
        0 => if (lBit(word) == 0)
            .{ .cmpw = .{ .crf = crf(word), .ra = ra(word), .rb = rb(word) } }
        else
            .{ .cmpd = .{ .crf = crf(word), .ra = ra(word), .rb = rb(word) } },
        4 => .{ .tw = .{ .to = @truncate((word >> 21) & 0x1f), .ra = ra(word), .rb = rb(word) } },
        8 => .{ .subfc = xForm(word) },
        10 => .{ .addc = xForm(word) },
        11 => .{ .mulhwu = xForm(word) },
        20 => .{ .lwarx = xForm(word) },
        21 => .{ .ldx = xForm(word) },
        24 => .{ .slw = xForm(word) },
        27 => .{ .sld = xForm(word) },
        32 => if (lBit(word) == 0)
            .{ .cmplw = .{ .crf = crf(word), .ra = ra(word), .rb = rb(word) } }
        else
            .{ .cmpld = .{ .crf = crf(word), .ra = ra(word), .rb = rb(word) } },
        40 => .{ .subf = xForm(word) },
        55 => .{ .lwzux = xForm(word) },
        60 => .{ .andc = xForm(word) },
        75 => .{ .mulhw = xForm(word) },
        83 => .{ .mfmsr = .{ .rt = rt(word) } },
        86 => .{ .dcbf = xForm(word) },
        104 => .{ .neg = xForm(word) },
        119 => .{ .lbzux = xForm(word) },
        124 => .{ .nor_ = xForm(word) },
        136 => .{ .subfe = xForm(word) },
        138 => .{ .adde = xForm(word) },
        144 => .{ .mtocrf = .{ .rt = rt(word), .crm = @truncate((word >> 12) & 0xff) } },
        149 => .{ .stdx = xForm(word) },
        150 => .{ .stwcx = xForm(word) },
        178 => .{ .mtmsrd = .{ .rt = rt(word) } },
        183 => .{ .stwux = xForm(word) },
        200 => .{ .subfze = xForm(word) },
        202 => .{ .addze = xForm(word) },
        232 => .{ .subfme = xForm(word) },
        233 => .{ .mulld = xForm(word) },
        247 => .{ .stbux = xForm(word) },
        235 => .{ .mullw = xForm(word) },
        266 => .{ .add = xForm(word) },
        278 => .{ .dcbt = xForm(word) },
        284 => .{ .eqv = xForm(word) },
        316 => .{ .xor_ = xForm(word) },
        339 => sprMove(word, false),
        19 => .{ .mfocrf = .{ .rt = rt(word), .crm = @truncate((word >> 12) & 0xff) } },
        343 => .{ .lhax = xForm(word) },
        375 => .{ .lhaux = xForm(word) },
        407 => .{ .sthx = xForm(word) },
        444 => .{ .or_ = xForm(word) },
        457 => .{ .divdu = xForm(word) },
        459 => .{ .divwu = xForm(word) },
        467 => sprMove(word, true),
        491 => .{ .divw = xForm(word) },
        534 => .{ .lwbrx = xForm(word) },
        536 => .{ .srw = xForm(word) },
        539 => .{ .srd = xForm(word) },
        598 => if (word & 0x0020_0000 != 0) .lwsync else .sync,
        662 => .{ .stwbrx = xForm(word) },
        663 => .{ .stfsx = .{ .frd = rt(word), .fra = ra(word), .frb = rb(word), .rc = word & 1 != 0 } },
        727 => .{ .stfdx = .{ .frd = rt(word), .fra = ra(word), .frb = rb(word), .rc = word & 1 != 0 } },
        790 => .{ .lhbrx = xForm(word) },
        792 => .{ .sraw = xForm(word) },
        824 => .{ .srawi = .{
            .ra = ra(word),
            .rs = rt(word),
            .sh = @truncate((word >> 11) & 0x1f),
            .rc = word & 1 != 0,
        } },
        854 => .eieio,
        918 => .{ .sthbrx = xForm(word) },
        922 => .{ .extsh = .{ .rt = rt(word), .ra = ra(word), .rb = 0, .rc = word & 1 != 0 } },
        954 => .{ .extsb = .{ .rt = rt(word), .ra = ra(word), .rb = 0, .rc = word & 1 != 0 } },
        982 => .{ .icbi = xForm(word) },
        983 => .{ .stfiwx = xForm(word) },
        986 => .{ .extsw = .{ .rt = rt(word), .ra = ra(word), .rb = 0, .rc = word & 1 != 0 } },
        1014 => .{ .dcbz = xForm(word) },
        26 => .{ .cntlzw = .{ .rt = rt(word), .ra = ra(word), .rb = 0, .rc = word & 1 != 0 } },
        28 => .{ .and_ = xForm(word) },
        23 => .{ .lwzx = xForm(word) },
        87 => .{ .lbzx = xForm(word) },
        151 => .{ .stwx = xForm(word) },
        215 => .{ .stbx = xForm(word) },
        279 => .{ .lwzx = xForm(word) },
        535 => .{ .lfsx = .{ .frd = rt(word), .fra = ra(word), .frb = rb(word), .rc = word & 1 != 0 } },
        599 => .{ .lfdx = .{ .frd = rt(word), .fra = ra(word), .frb = rb(word), .rc = word & 1 != 0 } },
        103 => .{ .lvx = vMemForm(word) },
        231 => .{ .stvx = vMemForm(word) },
        else => error.Unsupported,
    };
}

fn decodeAForm(word: u32, primary: u8) Error!Instruction {
    const xo5 = (word >> 1) & 0x1f;
    const fma = FMForm{ .frd = frd(word), .fra = fra(word), .frc = frc(word), .frb = frb(word), .rc = word & 1 != 0 };
    if (primary == 59) {
        return switch (xo5) {
            18 => .{ .fdivs = fForm(word) },
            20 => .{ .fsubs = fForm(word) },
            21 => .{ .fadds = fForm(word) },
            22 => .{ .fsqrts = fForm(word) },
            25 => .{ .fmuls = .{ .frd = frd(word), .fra = fra(word), .frb = frc(word), .rc = word & 1 != 0 } },
            28 => .{ .fmsubs = fma },
            29 => .{ .fmadds = fma },
            30 => .{ .fnmsubs = fma },
            31 => .{ .fnmadds = fma },
            else => error.Unsupported,
        };
    }
    switch (xo5) {
        25 => return .{ .fmul = .{ .frd = frd(word), .fra = fra(word), .frb = frc(word), .rc = word & 1 != 0 } },
        28 => return .{ .fmsub = fma },
        29 => return .{ .fmadd = fma },
        30 => return .{ .fnmsub = fma },
        31 => return .{ .fnmadd = fma },
        else => {},
    }
    const xo = (word >> 1) & 0x3ff;
    return switch (xo) {
        0 => .{ .fcmpu = .{ .crf = crf(word), .fra = fra(word), .frb = frb(word) } },
        15 => .{ .fctiwz = fForm(word) },
        18 => .{ .fdiv = fForm(word) },
        20 => .{ .fsub = fForm(word) },
        21 => .{ .fadd = fForm(word) },
        25 => .{ .fmul = .{ .frd = frd(word), .fra = fra(word), .frb = frc(word), .rc = word & 1 != 0 } },
        12 => .{ .frsp = fForm(word) },
        40 => .{ .fneg = fForm(word) },
        72 => .{ .fmr = fForm(word) },
        264 => .{ .fabs = fForm(word) },
        815 => .{ .fctidz = fForm(word) },
        846 => .{ .fcfid = fForm(word) },
        else => error.Unsupported,
    };
}

fn decodeVForm(word: u32) Error!Instruction {
    const xo6 = word & 0x3f;
    if (xo6 == 43) {
        return .{ .vperm = .{
            .vd = @truncate((word >> 21) & 0x1f),
            .va = @truncate((word >> 16) & 0x1f),
            .vb = @truncate((word >> 11) & 0x1f),
            .vc = @truncate((word >> 6) & 0x1f),
        } };
    }
    if (xo6 == 46) {
        return .{ .vmaddfp = .{
            .vd = @truncate((word >> 21) & 0x1f),
            .va = @truncate((word >> 16) & 0x1f),
            .vc = @truncate((word >> 11) & 0x1f),
            .vb = @truncate((word >> 6) & 0x1f),
        } };
    }
    if (xo6 == 12) {
        return .{ .vspltisw = .{
            .vd = @truncate((word >> 21) & 0x1f),
            .simm = @truncate(@as(i5, @bitCast(@as(u5, @truncate((word >> 16) & 0x1f))))),
        } };
    }
    const xo = word & 0x7ff;
    return switch (xo) {
        6 => .{ .vcmpequb = .{ .vd = rt(word), .va = ra(word), .vb = rb(word) } },
        518 => .{ .vcmpgtub = .{ .vd = rt(word), .va = ra(word), .vb = rb(word) } },
        1028 => .{ .vand = .{ .vd = rt(word), .va = ra(word), .vb = rb(word) } },
        74 => .{ .vsubfp = .{ .vd = rt(word), .va = ra(word), .vb = rb(word) } },
        132 => .{ .vrlw = .{ .vd = rt(word), .va = ra(word), .vb = rb(word) } },
        10 => .{ .vaddfp = .{ .vd = rt(word), .va = ra(word), .vb = rb(word) } },
        1220 => .{ .vxor = .{ .vd = rt(word), .va = ra(word), .vb = rb(word) } },
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

fn frd(word: u32) u8 {
    return @truncate((word >> 21) & 0x1f);
}

fn frc(word: u32) u8 {
    return @truncate((word >> 6) & 0x1f);
}

fn frb(word: u32) u8 {
    return @truncate((word >> 11) & 0x1f);
}

fn crOp(kind: CrKind, word: u32) Instruction {
    return .{ .cr_op = .{
        .kind = kind,
        .bt = @truncate((word >> 21) & 0x1f),
        .ba = @truncate((word >> 16) & 0x1f),
        .bb = @truncate((word >> 11) & 0x1f),
    } };
}

fn sprField(word: u32) u10 {
    const hi: u10 = @truncate((word >> 11) & 0x1f);
    const lo: u10 = @truncate((word >> 16) & 0x1f);
    return (hi << 5) | lo;
}

fn sprMove(word: u32, to: bool) Instruction {
    const spr = sprField(word);
    const reg = rt(word);
    if (to) {
        return switch (spr) {
            8 => .{ .mtlr = .{ .rt = reg } },
            9 => .{ .mtctr = .{ .rt = reg } },
            else => .{ .mtspr = .{ .rt = reg, .spr = spr } },
        };
    }
    return switch (spr) {
        8 => .{ .mflr = .{ .rt = reg } },
        9 => .{ .mfctr = .{ .rt = reg } },
        else => .{ .mfspr = .{ .rt = reg, .spr = spr } },
    };
}

fn addicForm(word: u32, rc: bool) AddicForm {
    const f = dForm(word);
    return .{ .rt = f.rt, .ra = f.ra, .imm = f.imm, .rc = rc };
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
    return .{ .rt = rt(word), .ra = ra(word), .rb = rb(word), .rc = word & 1 != 0 };
}

fn fForm(word: u32) FForm {
    return .{ .frd = rt(word), .fra = fra(word), .frb = frb(word), .rc = word & 1 != 0 };
}

fn vMemForm(word: u32) VMemForm {
    return .{ .vd = rt(word), .ra = ra(word), .rb = rb(word) };
}

fn branchForm(word: u32) BranchForm {
    const raw = word & 0x03ff_fffc;
    const offset = @as(i32, @bitCast(raw << 6)) >> 6;
    const absolute = word & 2 != 0;
    return .{
        .target = if (absolute) raw else @bitCast(offset),
        .absolute = absolute,
        .link = word & 1 != 0,
    };
}

/// `bclr`/`bcctr` bit 1 is the BH hint, not AA. Their target is a register.
fn bclrForm(word: u32) BcForm {
    var f = bcForm(word);
    f.absolute = false;
    return f;
}

fn bcForm(word: u32) BcForm {
    const raw = word & 0x0000_fffc;
    const offset = @as(i32, @bitCast(raw << 16)) >> 16;
    const absolute = word & 2 != 0;
    return .{
        .bo = bo(word),
        .bi = bi(word),
        .target = if (absolute) raw else @bitCast(offset),
        .absolute = absolute,
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

test "rldicr keeps the six-bit shift and mask" {
    try expectDecode(0x78834506, .{ .rldicr = .{ .ra = 3, .rs = 4, .sh = 40, .me = 20 } });
    try expectDecode(0x788357e4, .{ .rldicr = .{ .ra = 3, .rs = 4, .sh = 10, .me = 63 } });
}

test "bctr and bcctr are not returns" {
    const bctr = switch (try decode(0x4e800420)) {
        .bclr => |f| f,
        else => return error.TestExpectedBclr,
    };
    try testing.expect(bctr.to_ctr);
    try testing.expect(!bctr.link);
    try testing.expect(!isReturn(try decode(0x4e800420)));

    const bcctr = switch (try decode(0x4d800420)) {
        .bclr => |f| f,
        else => return error.TestExpectedBclr,
    };
    try testing.expect(bcctr.to_ctr);
    try testing.expect(!bcctr.link);
    try testing.expectEqual(@as(u5, 12), bcctr.bo);

    const bctrl = switch (try decode(0x4e800421)) {
        .bclr => |f| f,
        else => return error.TestExpectedBclr,
    };
    try testing.expect(bctrl.to_ctr);
    try testing.expect(bctrl.link);

    try expectDecode(0x4e800020, .blr);
}

test "record forms carry the rc bit" {
    try expectDecode(0x7c662851, .{ .subf = .{ .rt = 3, .ra = 6, .rb = 5, .rc = true } });
    try expectDecode(0x5483003f, .{ .rlwinm = .{ .ra = 3, .rs = 4, .sh = 0, .mb = 0, .me = 31, .rc = true } });
    try expectDecode(0x7c632215, .{ .add = .{ .rt = 3, .ra = 3, .rb = 4, .rc = true } });
    try expectDecode(0x7c632039, .{ .and_ = .{ .rt = 3, .ra = 3, .rb = 4, .rc = true } });
}

test "a-form float encodings use FRC and FRB correctly" {
    try expectDecode(0xFC210332, .{ .fmul = .{ .frd = 1, .fra = 1, .frb = 12 } });
    try expectDecode(0xFC21483A, .{ .fmadd = .{ .frd = 1, .fra = 1, .frc = 0, .frb = 9 } });
    try expectDecode(0xEC64C7F8, .{ .fmsubs = .{ .frd = 3, .fra = 4, .frc = 31, .frb = 24 } });
    try expectDecode(0xFFE0FA10, .{ .fabs = .{ .frd = 31, .fra = 0, .frb = 31 } });
}

test "integer and system encodings decode" {
    try expectDecode(0x356BFFFF, .{ .addic = .{ .rt = 11, .ra = 11, .imm = -1, .rc = true } });
    try expectDecode(0x7CA63110, .{ .subfe = .{ .rt = 5, .ra = 6, .rb = 6 } });
    try expectDecode(0x7D09DBD6, .{ .divw = .{ .rt = 8, .ra = 9, .rb = 27 } });
    try expectDecode(0x7C2004AC, .lwsync);
    try expectDecode(0x7D2000A6, .{ .mfmsr = .{ .rt = 9 } });
    try expectDecode(0x7D405828, .{ .lwarx = .{ .rt = 10, .ra = 0, .rb = 11 } });
    try expectDecode(0x7D40592D, .{ .stwcx = .{ .rt = 10, .ra = 0, .rb = 11, .rc = true } });
    try expectDecode(0x7D920120, .{ .mtocrf = .{ .rt = 12, .crm = 0x20 } });
}

test "unknown words are refused" {
    try testing.expectError(error.Unsupported, decode(0x00000000));
}
