//! Disc subsystem: ISO access and XDVDFS.

pub const iso = @import("iso.zig");
pub const xdvdfs = @import("xdvdfs.zig");

test {
    _ = iso;
    _ = xdvdfs;
}
