//! Minimal host behaviour for the imports boot actually reaches.
//! Everything else is logged by the generated stub and left untouched.

const Ctx = @import("ctx.zig").Ctx;

pub fn apply(name: []const u8, ordinal: u16, ctx: *Ctx) void {
    if (!std.mem.eql(u8, name, "xboxkrnl.exe")) return;
    switch (ordinal) {
        // RtlEnterCriticalSection
        0x125 => ctx.gpr[3] = 0,
        // XexCheckExecutablePrivilege
        0x194 => ctx.gpr[3] = 1,
        // ExGetXConfigSetting: success, zero the output buffer.
        0x10 => {
            const out: u32 = @truncate(ctx.gpr[5]);
            const size: u32 = @intCast(@min(ctx.gpr[6], 0x1000));
            var i: u32 = 0;
            while (i < size) : (i += 1) ctx.store8(out +% i, 0);
            ctx.gpr[3] = 0;
        },
        // KeTlsAlloc / KeTlsSetValue
        0x152 => ctx.gpr[3] = 0,
        0x155 => ctx.gpr[3] = 1,
        // RtlRaiseException: the guest is reporting a fatal init error.
        // Surface the whole record instead of returning into the halt loop.
        0x136 => raiseException(ctx),
        else => {},
    }
}

/// EXCEPTION_RECORD layout (all u32, big-endian guest memory).
const exc_code: u32 = 0;
const exc_flags: u32 = 4;
const exc_record: u32 = 8;
const exc_address: u32 = 12;
const exc_nparams: u32 = 16;
const exc_params: u32 = 20;

fn raiseException(ctx: *Ctx) void {
    const rec: u32 = @truncate(ctx.gpr[3]);
    const code = ctx.load32(rec +% exc_code);
    const flags = ctx.load32(rec +% exc_flags);
    const address = ctx.load32(rec +% exc_address);
    const nparams = ctx.load32(rec +% exc_nparams);
    std.debug.print("RtlRaiseException code=0x{X} flags=0x{X} addr=0x{X} params={d}", .{ code, flags, address, nparams });
    var i: u32 = 0;
    while (i < @min(nparams, 15)) : (i += 1) {
        std.debug.print(" 0x{X}", .{ctx.load32(rec +% exc_params +% i * 4)});
    }
    std.debug.print("\n", .{});
    ctx.gpr[3] = 0;
    ctx.fault = .{ .kind = .trap, .addr = rec };
}

const std = @import("std");
const FaultKind = @import("ctx.zig").FaultKind;

test "RtlRaiseException records a trap fault at the record" {
    var buf: [64]u8 = @splat(0);
    var ctx = Ctx.init(.{ .base = 0x1000, .data = &buf });
    // EXCEPTION_RECORD at 0x1000: code 0xC0000005, 2 params.
    ctx.store32(0x1000, 0xC0000005);
    ctx.store32(0x1004, 0);
    ctx.store32(0x100C, 0x83253790);
    ctx.store32(0x1010, 2);
    ctx.store32(0x1014, 0xDEAD0001);
    ctx.store32(0x1018, 0xDEAD0002);
    ctx.gpr[3] = 0x1000;
    apply("xboxkrnl.exe", 0x136, &ctx);
    try std.testing.expectEqual(FaultKind.trap, ctx.fault.kind);
    try std.testing.expectEqual(@as(u32, 0x1000), ctx.fault.addr);
}
