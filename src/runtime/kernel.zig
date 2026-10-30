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
        else => {},
    }
}

const std = @import("std");
