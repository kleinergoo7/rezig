//! AES-128-CBC decryption and XEX key loading.
//!
//! Implemented from FIPS-197. The S-box is derived at comptime from the GF(2^8)
//! inverse and the affine transform, so there is no hand-copied table.

const std = @import("std");
const Io = std.Io;

pub const LoadKeyError =
    std.Io.File.OpenError ||
    std.Io.File.StatError ||
    std.Io.File.ReadPositionalError ||
    error{BadKeySize};

pub const DecryptError = error{ LengthMismatch, NotBlockAligned };

pub fn loadKey(io: Io, path: []const u8, out: *[16]u8) LoadKeyError!void {
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    const st = try file.stat(io);
    if (st.size != 16) return error.BadKeySize;

    var buf: [16]u8 = undefined;
    const n = try file.readPositionalAll(io, &buf, 0);
    if (n != 16) return error.BadKeySize;
    out.* = buf;
}

pub fn decryptCbc(key: [16]u8, iv: [16]u8, input: []const u8, output: []u8) DecryptError!void {
    if (input.len != output.len) return error.LengthMismatch;
    if (input.len % 16 != 0) return error.NotBlockAligned;

    const round_keys = expandKey(key);
    var prev = iv;
    var i: usize = 0;
    while (i < input.len) : (i += 16) {
        const cipher = input[i..][0..16].*;
        var plain: [16]u8 = undefined;
        decryptBlock(&round_keys, &cipher, &plain);
        for (0..16) |j| plain[j] ^= prev[j];
        output[i..][0..16].* = plain;
        prev = cipher;
    }
}

fn xtime(a: u8) u8 {
    // Shift left in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1.
    return (a << 1) ^ (if (a & 0x80 != 0) @as(u8, 0x1b) else 0);
}

fn mul(a: u8, b: u8) u8 {
    var result: u8 = 0;
    var x = a;
    var y = b;
    var i: u4 = 0;
    while (i < 8) : (i += 1) {
        if (y & 1 != 0) result ^= x;
        x = xtime(x);
        y >>= 1;
    }
    return result;
}

fn inverse(x: u8) u8 {
    if (x == 0) return 0;
    var result: u8 = 1;
    var base = x;
    var exp: u8 = 254;
    while (exp != 0) : (exp >>= 1) {
        if (exp & 1 != 0) result = mul(result, base);
        base = mul(base, base);
    }
    return result;
}

fn rotl(x: u8, comptime n: u3) u8 {
    return (x << n) | (x >> @intCast(8 - @as(u4, n)));
}

fn affine(inv: u8) u8 {
    return inv ^ rotl(inv, 1) ^ rotl(inv, 2) ^ rotl(inv, 3) ^ rotl(inv, 4) ^ 0x63;
}

const sbox = blk: {
    @setEvalBranchQuota(200_000);
    var table: [256]u8 = undefined;
    for (0..256) |i| table[i] = affine(inverse(@intCast(i)));
    break :blk table;
};

const inv_sbox = blk: {
    var table: [256]u8 = undefined;
    for (0..256) |i| table[sbox[i]] = @intCast(i);
    break :blk table;
};

fn expandKey(key: [16]u8) [176]u8 {
    var rk: [176]u8 = undefined;
    @memcpy(rk[0..16], &key);

    var rcon: u8 = 1;
    var i: usize = 16;
    while (i < 176) : (i += 4) {
        var t = [4]u8{ rk[i - 4], rk[i - 3], rk[i - 2], rk[i - 1] };
        if (i % 16 == 0) {
            const first = t[0];
            t[0] = sbox[t[1]] ^ rcon;
            t[1] = sbox[t[2]];
            t[2] = sbox[t[3]];
            t[3] = sbox[first];
            rcon = xtime(rcon);
        }
        rk[i] = rk[i - 16] ^ t[0];
        rk[i + 1] = rk[i - 15] ^ t[1];
        rk[i + 2] = rk[i - 14] ^ t[2];
        rk[i + 3] = rk[i - 13] ^ t[3];
    }
    return rk;
}

fn addRoundKey(state: *[16]u8, round_keys: *const [176]u8, round: u8) void {
    const base = @as(usize, round) * 16;
    for (0..16) |i| state[i] ^= round_keys[base + i];
}

fn invShiftRows(state: *[16]u8) void {
    var out: [16]u8 = undefined;
    for (0..4) |c| {
        for (0..4) |r| {
            out[r + 4 * c] = state[r + 4 * ((c + 4 - r) % 4)];
        }
    }
    state.* = out;
}

fn invSubBytes(state: *[16]u8) void {
    for (state) |*b| b.* = inv_sbox[b.*];
}

fn invMixColumns(state: *[16]u8) void {
    for (0..4) |c| {
        const a0 = state[4 * c];
        const a1 = state[4 * c + 1];
        const a2 = state[4 * c + 2];
        const a3 = state[4 * c + 3];
        state[4 * c] = mul(a0, 14) ^ mul(a1, 11) ^ mul(a2, 13) ^ mul(a3, 9);
        state[4 * c + 1] = mul(a0, 9) ^ mul(a1, 14) ^ mul(a2, 11) ^ mul(a3, 13);
        state[4 * c + 2] = mul(a0, 13) ^ mul(a1, 9) ^ mul(a2, 14) ^ mul(a3, 11);
        state[4 * c + 3] = mul(a0, 11) ^ mul(a1, 13) ^ mul(a2, 9) ^ mul(a3, 14);
    }
}

fn decryptBlock(round_keys: *const [176]u8, input: *const [16]u8, output: *[16]u8) void {
    var state = input.*;
    addRoundKey(&state, round_keys, 10);

    var round: u8 = 9;
    while (round > 0) : (round -= 1) {
        invShiftRows(&state);
        invSubBytes(&state);
        addRoundKey(&state, round_keys, round);
        invMixColumns(&state);
    }

    invShiftRows(&state);
    invSubBytes(&state);
    addRoundKey(&state, round_keys, 0);
    output.* = state;
}

fn hexBytes(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch @panic("test hex literal is invalid");
    return out;
}

const testing = std.testing;

test "fips-197 appendix c.1 block decrypts" {
    const key = hexBytes("000102030405060708090a0b0c0d0e0f");
    const cipher = hexBytes("69c4e0d86a7b0430d8cdb78070b4c55a");
    const expected = hexBytes("00112233445566778899aabbccddeeff");
    const iv = std.mem.zeroes([16]u8);

    var out: [16]u8 = undefined;
    try decryptCbc(key, iv, &cipher, &out);
    try testing.expectEqualSlices(u8, &expected, &out);
}

test "nist sp 800-38a cbc-128 decrypt vector" {
    const key = hexBytes("2b7e151628aed2a6abf7158809cf4f3c");
    const iv = hexBytes("000102030405060708090a0b0c0d0e0f");
    const cipher = hexBytes(
        "7649abac8119b246cee98e9b12e9197d" ++
            "5086cb9b507219ee95db113a917678b2" ++
            "73bed6b8e3c1743b7116e69e22229516" ++
            "3ff1caa1681fac09120eca307586e1a7",
    );
    const expected = hexBytes(
        "6bc1bee22e409f96e93d7e117393172a" ++
            "ae2d8a571e03ac9c9eb76fac45af8e51" ++
            "30c81c46a35ce411e5fbc1191a0a52ef" ++
            "f69f2445df4f9b17ad2b417be66c3710",
    );

    var out: [64]u8 = undefined;
    try decryptCbc(key, iv, &cipher, &out);
    try testing.expectEqualSlices(u8, &expected, &out);
}

test "length mismatch is rejected" {
    const key = std.mem.zeroes([16]u8);
    const iv = std.mem.zeroes([16]u8);
    var out: [32]u8 = undefined;
    const input = std.mem.zeroes([16]u8);
    try testing.expectError(error.LengthMismatch, decryptCbc(key, iv, &input, &out));
}

test "non block aligned input is rejected" {
    const key = std.mem.zeroes([16]u8);
    const iv = std.mem.zeroes([16]u8);
    var out: [15]u8 = undefined;
    const input: [15]u8 = undefined;
    try testing.expectError(error.NotBlockAligned, decryptCbc(key, iv, &input, &out));
}

test "loadKey accepts exactly sixteen bytes" {
    const io = Io.Threaded.global_single_threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const key = hexBytes("000102030405060708090a0b0c0d0e0f");
    try tmp.dir.writeFile(io, .{ .sub_path = "key.bin", .data = &key });

    var path_buf: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/key.bin", .{tmp.sub_path});

    var loaded: [16]u8 = undefined;
    try loadKey(io, path, &loaded);
    try testing.expectEqualSlices(u8, &key, &loaded);
}

test "loadKey rejects a thirty-two byte file" {
    const io = Io.Threaded.global_single_threaded.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const key = std.mem.zeroes([32]u8);
    try tmp.dir.writeFile(io, .{ .sub_path = "key.bin", .data = &key });

    var path_buf: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/key.bin", .{tmp.sub_path});

    var loaded: [16]u8 = undefined;
    try testing.expectError(error.BadKeySize, loadKey(io, path, &loaded));
}
