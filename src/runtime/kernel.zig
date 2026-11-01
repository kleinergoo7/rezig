//! Minimal host behaviour for the imports boot actually reaches.
//! Everything else is logged by the generated stub and left untouched.

const std = @import("std");
const Ctx = @import("ctx.zig").Ctx;
const ctx_mod = @import("ctx.zig");
const FaultKind = ctx_mod.FaultKind;

/// Bump allocator over the tail of the guest image. Single-threaded boot.
/// The heap lives in the last 1 MiB below the initial stack reserve so it
/// never collides with image data or the guest stack.
const heap_size: u32 = 1 << 20;
const stack_reserve: u32 = 0x100;

var heap_base: u32 = 0;
var heap_cursor: u32 = 0;
var heap_end: u32 = 0;

fn heapInit(ctx: *Ctx) void {
    if (heap_base != 0) return;
    const total = ctx.mem.base +% @as(u32, @intCast(ctx.mem.data.len));
    // Leave the stack reserve at the very top.
    heap_end = total -% stack_reserve;
    if (heap_end < heap_size +% 0x1000) return; // too small, leave disabled
    heap_base = heap_end -% heap_size;
    heap_cursor = heap_base;
}

fn heapAlloc(ctx: *Ctx, size: u32) u32 {
    heapInit(ctx);
    if (heap_base == 0) return 0;
    // 16-byte alignment.
    const aligned = (heap_cursor + 15) & ~@as(u32, 15);
    const next = aligned +% size;
    if (next > heap_end or next < aligned) return 0; // overflow or OOM
    heap_cursor = next;
    // Zero the block so uninitialized reads are deterministic.
    var i: u32 = 0;
    while (i < size) : (i += 1) ctx.store8(aligned +% i, 0);
    return aligned;
}

pub fn apply(name: []const u8, ordinal: u16, ctx: *Ctx) void {
    if (!std.mem.eql(u8, name, "xboxkrnl.exe")) return;
    switch (ordinal) {
        // RtlEnterCriticalSection
        0x125 => ctx.gpr[3] = 0,
        // RtlLeaveCriticalSection
        0x130 => ctx.gpr[3] = 0,
        // RtlTryEnterCriticalSection
        0x141 => ctx.gpr[3] = 1,
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
        // KeTlsAlloc / KeTlsSetValue / KeTlsGetValue / KeTlsFree
        0x152 => ctx.gpr[3] = 0, // alloc slot 0
        0x153 => ctx.gpr[3] = 0, // free: success
        0x154 => ctx.gpr[3] = 0, // get value: null
        0x155 => ctx.gpr[3] = 1, // set value: success
        // RtlInitializeCriticalSection / ...AndSpinCount
        0x12E, 0x12F => ctx.gpr[3] = 0,
        // RtlRaiseException: surface the record, then fault.
        0x136 => raiseException(ctx),
        // Pool allocators: r4 = byte count.
        0x9, 0xA, 0xB => {
            const size: u32 = @truncate(ctx.gpr[4]);
            ctx.gpr[3] = heapAlloc(ctx, size);
        },
        // ExFreePool / ExFreePoolWithTag
        0xF => {},
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
    const nparams = ctx.load32(rec +% exc_params);
    // nparams is at +16, not +20; reload correctly.
    const np = ctx.load32(rec +% exc_nparams);
    std.debug.print("RtlRaiseException code=0x{X} flags=0x{X} addr=0x{X} params={d}", .{ code, flags, address, np });
    var i: u32 = 0;
    while (i < @min(np, 15)) : (i += 1) {
        std.debug.print(" 0x{X}", .{ctx.load32(rec +% exc_params +% i * 4)});
    }
    std.debug.print("\n", .{});
    _ = nparams;
    ctx.gpr[3] = 0;
    ctx.fault = .{ .kind = .trap, .addr = rec };
}

test "RtlRaiseException records a trap fault at the record" {
    var buf: [64]u8 = @splat(0);
    var ctx = Ctx.init(.{ .base = 0x1000, .data = &buf });
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

test "heap alloc returns an in-window pointer and zeroes" {
    var buf: [1 << 21]u8 = @splat(0);
    var ctx = Ctx.init(.{ .base = 0x1000, .data = &buf });
    ctx.gpr[4] = 64;
    apply("xboxkrnl.exe", 0x99, &ctx); // unrelated, no-op for heap
    // Reset module state by calling heapAlloc directly via an alloc ordinal.
    heap_base = 0;
    heap_cursor = 0;
    heap_end = 0;
    ctx.gpr[4] = 64;
    apply("xboxkrnl.exe", 0x9, &ctx);
    const p = @as(u32, @truncate(ctx.gpr[3]));
    try std.testing.expect(p != 0);
    try std.testing.expect(ctx.mem.contains(p, 64));
    var i: u32 = 0;
    while (i < 64) : (i += 1) try std.testing.expectEqual(@as(u8, 0), ctx.load8(p +% i));
}

test "alloc returns 0 when the request exceeds the heap" {
    var buf: [1 << 21]u8 = @splat(0);
    var ctx = Ctx.init(.{ .base = 0x1000, .data = &buf });
    heap_base = 0;
    heap_cursor = 0;
    heap_end = 0;
    ctx.gpr[4] = heap_size + 1;
    apply("xboxkrnl.exe", 0x9, &ctx);
    try std.testing.expectEqual(@as(u64, 0), ctx.gpr[3]);
}

test "unknown ordinal is a no-op" {
    var buf: [16]u8 = @splat(0);
    var ctx = Ctx.init(.{ .base = 0x1000, .data = &buf });
    ctx.gpr[3] = 0x1234;
    apply("xboxkrnl.exe", 0xFFFF, &ctx);
    try std.testing.expectEqual(@as(u64, 0x1234), ctx.gpr[3]);
}
