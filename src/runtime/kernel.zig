//! Minimal host behaviour for the imports boot actually reaches.
//! Everything else is logged by the generated stub and left untouched.

const std = @import("std");
const Ctx = @import("ctx.zig").Ctx;
const ctx_mod = @import("ctx.zig");
const FaultKind = ctx_mod.FaultKind;

/// Bump allocator over the guest arena the harness provides. Single-threaded
/// boot; frees are no-ops.
var heap_base: u32 = 0;
var heap_cursor: u32 = 0;
var heap_end: u32 = 0;

/// Xenon allocation flags: 64 KiB pages (0x4000_0000) and large pages
/// (0x2000_0000) both require 64 KiB alignment.
const xenon_page_flags: u32 = 0x6000_0000;
const page_4k: u32 = 0x1000;
const page_64k: u32 = 0x10000;
const status_invalid_parameter: u32 = 0xC000_000D;
const status_no_memory: u32 = 0xC000_0017;

fn heapInit(ctx: *Ctx) void {
    if (heap_base != 0) return;
    if (ctx.arena_base == 0 or ctx.arena_end <= ctx.arena_base) return;
    heap_base = ctx.arena_base;
    heap_cursor = ctx.arena_base;
    heap_end = ctx.arena_end;
}

fn heapAllocAligned(ctx: *Ctx, size: u32, alignment: u32) u32 {
    heapInit(ctx);
    if (heap_base == 0) return 0;
    const aligned = (heap_cursor + (alignment - 1)) & ~(alignment - 1);
    const next = aligned +% size;
    if (next > heap_end or next < aligned) return 0; // overflow or OOM
    heap_cursor = next;
    // Arena memory starts zeroed; keep later allocations deterministic too.
    var i: u32 = 0;
    while (i < size) : (i += 1) ctx.store8(aligned +% i, 0);
    return aligned;
}

fn heapAlloc(ctx: *Ctx, size: u32) u32 {
    return heapAllocAligned(ctx, size, 16);
}

/// Initial thread's TEB: the guest reads `r13 + 256` for its TLS area, so
/// `r13` must point at a zeroed block before the entry point runs.
const teb_size: u32 = 0x400;
const teb_tls_offset: u32 = 256;
const tls_size: u32 = 0x400;

pub fn initThread(ctx: *Ctx) void {
    const tls = heapAllocAligned(ctx, tls_size, 16);
    const teb = heapAllocAligned(ctx, teb_size, 16);
    if (tls == 0 or teb == 0) {
        std.debug.print("initThread: out of arena memory for the TEB\n", .{});
        ctx.failUnsupported(0);
        return;
    }
    ctx.store32(teb +% teb_tls_offset, tls);
    ctx.gpr[13] = teb;
}

/// NtAllocateVirtualMemory(base_addr*, region_size*, alloc_type, protect).
fn allocateVirtual(ctx: *Ctx) void {
    const base_ptr: u32 = @truncate(ctx.gpr[3]);
    const size_ptr: u32 = @truncate(ctx.gpr[4]);
    const alloc_type: u32 = @truncate(ctx.gpr[5]);
    // The guest may only ask for read/write memory here. Anything else would
    // need real page protection, which the arena does not model.
    _ = ctx.gpr[6];
    const requested: u32 = @truncate(ctx.load32(size_ptr));
    if (requested == 0) {
        ctx.gpr[3] = status_invalid_parameter;
        return;
    }
    const alignment: u32 = if (alloc_type & xenon_page_flags != 0) page_64k else page_4k;
    const hint: u32 = @truncate(ctx.load32(base_ptr));
    if (hint != 0) {
        // Fixed mapping: only honest when the whole range sits inside the
        // arena. The bump cursor moves past it so later allocations never
        // overlap.
        heapInit(ctx);
        const size = (requested + (alignment - 1)) & ~(alignment - 1);
        const end = hint +% size;
        if (heap_base == 0 or end < hint or hint < heap_base or end > heap_end) {
            std.debug.print("NtAllocateVirtualMemory: requested range 0x{X}+0x{X} is outside the arena\n", .{ hint, size });
            ctx.failUnsupported(hint);
            return;
        }
        var i: u32 = 0;
        while (i < size) : (i += 1) ctx.store8(hint +% i, 0);
        if (end > heap_cursor) heap_cursor = end;
        ctx.store32(base_ptr, hint);
        ctx.store32(size_ptr, size);
        ctx.gpr[3] = 0;
        return;
    }
    const size = (requested + (alignment - 1)) & ~(alignment - 1);
    const p = heapAllocAligned(ctx, size, alignment);
    if (p == 0) {
        ctx.gpr[3] = status_no_memory;
        return;
    }
    ctx.store32(base_ptr, p);
    ctx.store32(size_ptr, size);
    ctx.gpr[3] = 0;
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
        // NtAllocateVirtualMemory
        0xCC => allocateVirtual(ctx),
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
    ctx.arena_base = 0x1000;
    ctx.arena_end = 0x1000 + @as(u32, @intCast(buf.len));
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

test "alloc returns 0 when the request exceeds the arena" {
    var buf: [1 << 21]u8 = @splat(0);
    var ctx = Ctx.init(.{ .base = 0x1000, .data = &buf });
    ctx.arena_base = 0x1000;
    ctx.arena_end = 0x1000 + 0x1000;
    heap_base = 0;
    heap_cursor = 0;
    heap_end = 0;
    ctx.gpr[4] = 0x1001;
    apply("xboxkrnl.exe", 0x9, &ctx);
    try std.testing.expectEqual(@as(u64, 0), ctx.gpr[3]);
}

test "NtAllocateVirtualMemory writes a 64 KiB-aligned base and size" {
    var buf: [1 << 21]u8 = @splat(0);
    var ctx = Ctx.init(.{ .base = 0x1000, .data = &buf });
    ctx.arena_base = 0x1000;
    ctx.arena_end = 0x1000 + @as(u32, @intCast(buf.len));
    heap_base = 0;
    heap_cursor = 0;
    heap_end = 0;
    const base_cell: u32 = 0x1F0000;
    const size_cell: u32 = 0x1F0004;
    ctx.store32(base_cell, 0);
    ctx.store32(size_cell, 0x1234);
    ctx.gpr[3] = base_cell;
    ctx.gpr[4] = size_cell;
    ctx.gpr[5] = 0x60002000;
    ctx.gpr[6] = 4;
    apply("xboxkrnl.exe", 0xCC, &ctx);
    try std.testing.expectEqual(@as(u64, 0), ctx.gpr[3]);
    const base = ctx.load32(base_cell);
    try std.testing.expectEqual(@as(u32, 0), base & 0xFFFF);
    try std.testing.expectEqual(@as(u32, 0x10000), ctx.load32(size_cell));
}

test "NtAllocateVirtualMemory rejects a zero size" {
    var buf: [1 << 21]u8 = @splat(0);
    var ctx = Ctx.init(.{ .base = 0x1000, .data = &buf });
    ctx.arena_base = 0x1000;
    ctx.arena_end = 0x1000 + @as(u32, @intCast(buf.len));
    heap_base = 0;
    heap_cursor = 0;
    heap_end = 0;
    const base_cell: u32 = 0x1F0000;
    const size_cell: u32 = 0x1F0004;
    ctx.store32(base_cell, 0);
    ctx.store32(size_cell, 0);
    ctx.gpr[3] = base_cell;
    ctx.gpr[4] = size_cell;
    ctx.gpr[5] = 0x3000;
    ctx.gpr[6] = 4;
    apply("xboxkrnl.exe", 0xCC, &ctx);
    try std.testing.expectEqual(@as(u64, status_invalid_parameter), ctx.gpr[3]);
}

test "NtAllocateVirtualMemory honors an in-arena fixed base" {
    var buf: [1 << 21]u8 = @splat(0xFF);
    var ctx = Ctx.init(.{ .base = 0x1000, .data = &buf });
    ctx.arena_base = 0x1000;
    ctx.arena_end = 0x1000 + @as(u32, @intCast(buf.len));
    heap_base = 0;
    heap_cursor = 0;
    heap_end = 0;
    const base_cell: u32 = 0x1F0000;
    const size_cell: u32 = 0x1F0004;
    ctx.store32(base_cell, 0x11000);
    ctx.store32(size_cell, 0x2000);
    ctx.gpr[3] = base_cell;
    ctx.gpr[4] = size_cell;
    ctx.gpr[5] = 0x3000;
    ctx.gpr[6] = 4;
    apply("xboxkrnl.exe", 0xCC, &ctx);
    try std.testing.expectEqual(@as(u64, 0), ctx.gpr[3]);
    try std.testing.expectEqual(@as(u64, 0x11000), ctx.load32(base_cell));
    try std.testing.expectEqual(@as(u64, 0), ctx.load8(0x11000));
    // A later bump allocation must not overlap the fixed range.
    ctx.gpr[4] = 16;
    apply("xboxkrnl.exe", 0x9, &ctx);
    try std.testing.expect(ctx.gpr[3] >= 0x13000);
}

test "NtAllocateVirtualMemory refuses a fixed base outside the arena" {
    var buf: [1 << 21]u8 = @splat(0);
    var ctx = Ctx.init(.{ .base = 0x1000, .data = &buf });
    ctx.arena_base = 0x1000;
    ctx.arena_end = 0x1000 + @as(u32, @intCast(buf.len));
    heap_base = 0;
    heap_cursor = 0;
    heap_end = 0;
    const base_cell: u32 = 0x1F0000;
    const size_cell: u32 = 0x1F0004;
    ctx.store32(base_cell, 0x50000000);
    ctx.store32(size_cell, 0x1000);
    ctx.gpr[3] = base_cell;
    ctx.gpr[4] = size_cell;
    ctx.gpr[5] = 0x3000;
    ctx.gpr[6] = 4;
    apply("xboxkrnl.exe", 0xCC, &ctx);
    try std.testing.expectEqual(FaultKind.unsupported, ctx.fault.kind);
}

test "initThread points r13 at a TEB with a TLS area" {
    var buf: [1 << 21]u8 = @splat(0);
    var ctx = Ctx.init(.{ .base = 0x1000, .data = &buf });
    ctx.arena_base = 0x1000;
    ctx.arena_end = 0x1000 + @as(u32, @intCast(buf.len));
    heap_base = 0;
    heap_cursor = 0;
    heap_end = 0;
    initThread(&ctx);
    const teb: u32 = @truncate(ctx.gpr[13]);
    try std.testing.expect(teb != 0);
    try std.testing.expect(ctx.mem.contains(teb, 1));
    try std.testing.expect(ctx.mem.contains(teb +% teb_size -% 1, 1));
    const tls = ctx.load32(teb +% teb_tls_offset);
    try std.testing.expect(tls != 0);
    try std.testing.expect(ctx.mem.contains(@truncate(tls), 1));
}

test "unknown ordinal is a no-op" {
    var buf: [16]u8 = @splat(0);
    var ctx = Ctx.init(.{ .base = 0x1000, .data = &buf });
    ctx.gpr[3] = 0x1234;
    apply("xboxkrnl.exe", 0xFFFF, &ctx);
    try std.testing.expectEqual(@as(u64, 0x1234), ctx.gpr[3]);
}
