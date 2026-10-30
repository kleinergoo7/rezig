//! argv parsing for the rezig CLI.

const std = @import("std");

pub const Extract = struct { iso: []const u8, out: []const u8, key: ?[]const u8 };
pub const Analyze = struct { tree: ?[]const u8, xex: ?[]const u8, key: ?[]const u8 };
pub const Xex = struct { in: []const u8, out: []const u8, key: ?[]const u8 };
pub const Codegen = struct {
    tree: ?[]const u8,
    xex: ?[]const u8,
    key: ?[]const u8,
    out: []const u8,
    slice: ?u32,
    slice_list: ?[]const u8,
};
pub const Build = struct { tree: []const u8 };
pub const Run = struct { tree: []const u8 };

pub const Command = union(enum) {
    extract: Extract,
    analyze: Analyze,
    coverage: Analyze,
    xex_convert: Xex,
    codegen: Codegen,
    build: Build,
    run: Run,
    help,
};

pub const ParseError = error{ Usage, UnknownCommand, MissingOption, UnknownOption, BadValue };

const Options = struct {
    iso: ?[]const u8 = null,
    in: ?[]const u8 = null,
    out: ?[]const u8 = null,
    key: ?[]const u8 = null,
    tree: ?[]const u8 = null,
    xex: ?[]const u8 = null,
    slice: ?u32 = null,
    slice_list: ?[]const u8 = null,

    fn set(self: *Options, comptime field: []const u8, value: anytype) ParseError!void {
        if (@field(self, field) != null) return error.BadValue;
        @field(self, field) = value;
    }

    fn require(self: *const Options, comptime field: []const u8) ParseError![]const u8 {
        return @field(self, field) orelse error.MissingOption;
    }

    fn rejectUnused(self: *const Options, comptime fields: []const []const u8) ParseError!void {
        inline for (fields) |field| {
            if (@field(self, field) != null) return error.UnknownOption;
        }
    }
};

pub fn parse(args: []const [:0]const u8) ParseError!Command {
    if (args.len < 2) return error.Usage;
    const name: []const u8 = args[1];

    if (std.mem.eql(u8, name, "help")) {
        if (args.len != 2) return error.Usage;
        return .help;
    }

    var opts: Options = .{};
    var i: usize = 2;
    while (i < args.len) {
        const flag: []const u8 = args[i];
        if (!std.mem.startsWith(u8, flag, "--")) return error.UnknownOption;
        if (i + 1 >= args.len) return error.MissingOption;
        const value: []const u8 = args[i + 1];
        i += 2;

        if (std.mem.eql(u8, flag, "--in")) {
            try opts.set("in", value);
        } else if (std.mem.eql(u8, flag, "--iso")) {
            try opts.set("iso", value);
        } else if (std.mem.eql(u8, flag, "--out")) {
            try opts.set("out", value);
        } else if (std.mem.eql(u8, flag, "--key")) {
            try opts.set("key", value);
        } else if (std.mem.eql(u8, flag, "--tree")) {
            try opts.set("tree", value);
        } else if (std.mem.eql(u8, flag, "--xex")) {
            try opts.set("xex", value);
        } else if (std.mem.eql(u8, flag, "--slice")) {
            const n = std.fmt.parseInt(u32, value, 10) catch return error.BadValue;
            try opts.set("slice", n);
        } else if (std.mem.eql(u8, flag, "--slice-list")) {
            try opts.set("slice_list", value);
        } else {
            return error.UnknownOption;
        }
    }

    if (std.mem.eql(u8, name, "extract")) {
        const iso = try opts.require("iso");
        const out = try opts.require("out");
        try opts.rejectUnused(&.{ "in", "tree", "xex", "slice", "slice_list" });
        return .{ .extract = .{ .iso = iso, .out = out, .key = opts.key } };
    }
    if (std.mem.eql(u8, name, "analyze")) {
        try opts.rejectUnused(&.{ "iso", "in", "out", "slice", "slice_list" });
        const has_tree = opts.tree != null;
        const has_xex = opts.xex != null;
        if (has_tree == has_xex) return if (has_tree) error.BadValue else error.MissingOption;
        return .{ .analyze = .{ .tree = opts.tree, .xex = opts.xex, .key = opts.key } };
    }
    if (std.mem.eql(u8, name, "coverage")) {
        try opts.rejectUnused(&.{ "iso", "in", "out", "slice", "slice_list" });
        const has_tree = opts.tree != null;
        const has_xex = opts.xex != null;
        if (has_tree == has_xex) return if (has_tree) error.BadValue else error.MissingOption;
        return .{ .coverage = .{ .tree = opts.tree, .xex = opts.xex, .key = opts.key } };
    }
    if (std.mem.eql(u8, name, "xex")) {
        const input = try opts.require("in");
        const out = try opts.require("out");
        try opts.rejectUnused(&.{ "iso", "tree", "xex", "slice", "slice_list" });
        return .{ .xex_convert = .{ .in = input, .out = out, .key = opts.key } };
    }
    if (std.mem.eql(u8, name, "codegen")) {
        const out = try opts.require("out");
        try opts.rejectUnused(&.{ "iso", "in" });
        const has_tree = opts.tree != null;
        const has_xex = opts.xex != null;
        if (has_tree == has_xex) return if (has_tree) error.BadValue else error.MissingOption;
        if (opts.slice != null and opts.slice_list != null) return error.BadValue;
        if (opts.slice == null and opts.slice_list == null) return error.MissingOption;
        return .{ .codegen = .{
            .tree = opts.tree,
            .xex = opts.xex,
            .key = opts.key,
            .out = out,
            .slice = opts.slice,
            .slice_list = opts.slice_list,
        } };
    }
    if (std.mem.eql(u8, name, "build") or std.mem.eql(u8, name, "run")) {
        const tree = try opts.require("tree");
        try opts.rejectUnused(&.{ "iso", "in", "out", "key", "xex", "slice", "slice_list" });
        if (std.mem.eql(u8, name, "build")) return .{ .build = .{ .tree = tree } };
        return .{ .run = .{ .tree = tree } };
    }
    return error.UnknownCommand;
}

const testing = std.testing;

test "no arguments is usage" {
    try testing.expectError(error.Usage, parse(&.{"rezig"}));
}

test "help command" {
    try testing.expectEqual(Command.help, try parse(&.{ "rezig", "help" }));
}

test "extract without key" {
    const cmd = try parse(&.{ "rezig", "extract", "--iso", "a.iso", "--out", "d" });
    try testing.expectEqualStrings("a.iso", cmd.extract.iso);
    try testing.expectEqualStrings("d", cmd.extract.out);
    try testing.expectEqual(@as(?[]const u8, null), cmd.extract.key);
}

test "extract with key" {
    const cmd = try parse(&.{ "rezig", "extract", "--iso", "a.iso", "--out", "d", "--key", "k" });
    try testing.expectEqualStrings("k", cmd.extract.key.?);
}

test "extract without out is missing option" {
    try testing.expectError(error.MissingOption, parse(&.{ "rezig", "extract", "--iso", "a.iso" }));
}

test "extract with trailing option value is missing option" {
    try testing.expectError(error.MissingOption, parse(&.{ "rezig", "extract", "--iso" }));
}

test "analyze without key is allowed" {
    const cmd = try parse(&.{ "rezig", "analyze", "--tree", "t" });
    try testing.expectEqualStrings("t", cmd.analyze.tree.?);
    try testing.expectEqual(@as(?[]const u8, null), cmd.analyze.key);
}

test "analyze accepts a direct xex and a key" {
    const cmd = try parse(&.{ "rezig", "analyze", "--xex", "a.xex", "--key", "k" });
    try testing.expectEqualStrings("a.xex", cmd.analyze.xex.?);
    try testing.expectEqualStrings("k", cmd.analyze.key.?);
}

test "analyze needs exactly one input" {
    try testing.expectError(error.MissingOption, parse(&.{ "rezig", "analyze" }));
    try testing.expectError(error.BadValue, parse(&.{ "rezig", "analyze", "--tree", "t", "--xex", "a.xex" }));
}

test "unknown command" {
    try testing.expectError(error.UnknownCommand, parse(&.{ "rezig", "wat" }));
}

test "unknown option" {
    try testing.expectError(error.UnknownOption, parse(&.{ "rezig", "analyze", "--tree", "t", "--key", "k", "--nope", "x" }));
}

test "duplicate option is bad value" {
    try testing.expectError(error.BadValue, parse(&.{ "rezig", "extract", "--iso", "a", "--iso", "b", "--out", "d" }));
}

test "coverage needs exactly one input" {
    try testing.expectError(error.MissingOption, parse(&.{ "rezig", "coverage" }));
    try testing.expectError(error.BadValue, parse(&.{ "rezig", "coverage", "--tree", "t", "--xex", "a.xex" }));
}

test "coverage accepts a key" {
    const cmd = try parse(&.{ "rezig", "coverage", "--xex", "a.xex", "--key", "k" });
    try testing.expectEqualStrings("a.xex", cmd.coverage.xex.?);
    try testing.expectEqualStrings("k", cmd.coverage.key.?);
}

test "xex needs input and output" {
    try testing.expectError(error.MissingOption, parse(&.{ "rezig", "xex", "--in", "a.xex" }));
    try testing.expectError(error.MissingOption, parse(&.{ "rezig", "xex", "--out", "b.xex" }));
}

test "xex accepts a key" {
    const cmd = try parse(&.{ "rezig", "xex", "--in", "a.xex", "--out", "b.xex", "--key", "k" });
    try testing.expectEqualStrings("a.xex", cmd.xex_convert.in);
    try testing.expectEqualStrings("b.xex", cmd.xex_convert.out);
    try testing.expectEqualStrings("k", cmd.xex_convert.key.?);
}

test "xex rejects an unrelated option" {
    try testing.expectError(error.UnknownOption, parse(&.{ "rezig", "xex", "--in", "a", "--out", "b", "--slice", "20" }));
}

test "codegen needs a slice source" {
    try testing.expectError(error.MissingOption, parse(&.{ "rezig", "codegen", "--tree", "t", "--key", "k", "--out", "o" }));
}

test "codegen rejects both slice sources" {
    try testing.expectError(error.BadValue, parse(&.{
        "rezig",   "codegen", "--tree",       "t",      "--key", "k", "--out", "o",
        "--slice", "20",      "--slice-list", "l.json",
    }));
}

test "codegen slice parses number" {
    const cmd = try parse(&.{ "rezig", "codegen", "--tree", "t", "--key", "k", "--out", "o", "--slice", "20" });
    try testing.expectEqual(@as(u32, 20), cmd.codegen.slice.?);
}

test "codegen slice rejects non number" {
    try testing.expectError(error.BadValue, parse(&.{
        "rezig", "codegen", "--tree", "t", "--key", "k", "--out", "o", "--slice", "notanumber",
    }));
}
