use std::error::Error;
use crate::MemoryMapEntryPermissionsKind;

#[test]
pub fn when_parse_memory_map_then_result_is_success() -> Result<(), Box<dyn Error>> {
    let sample = "aaaad9d30000-aaaad9d31000 r-xp 00000000 fc:02 7219570                    /home/cub3d/Documents/pid-stuff/a.out\n
aaab0ad73000-aaab0ad94000 rw-p 00000000 00:00 0                          [heap]\n
ffff85665000-ffff857c0000 r-xp 00000000 fc:02 262780                     /usr/lib/aarch64-linux-gnu/libc-2.31.so\n
ffff857d5000-ffff857d8000 rw-p 00000000 00:00 0\n
ffff857e8000-ffff85809000 r-xp 00000000 fc:02 262776                     /usr/lib/aarch64-linux-gnu/ld-2.31.so\n
ffff85814000-ffff85816000 rw-p 00000000 00:00 0\n
ffff85816000-ffff85818000 r--p 00000000 00:00 0                          [vvar]\n
ffff85818000-ffff85819000 r-xp 00000000 00:00 0                          [vdso]\n
ffff85819000-ffff8581a000 r--p 00021000 fc:02 262776                     /usr/lib/aarch64-linux-gnu/ld-2.31.so\n
ffffdbd5f000-ffffdbd80000 rw-p 00000000 00:00 0                          [stack]\n";

    let maps = crate::parse_memory_map(sample);
    assert_eq!(maps.is_some(), true);
    let maps = maps.unwrap();
    assert_eq!(maps.len(), 10);

    let m1 = maps.first().unwrap();
    assert_eq!(m1.path, "/home/cub3d/Documents/pid-stuff/a.out");
    assert_eq!(m1.permissions.read, true);
    assert_eq!(m1.permissions.write, false);
    assert_eq!(m1.permissions.execute, true);
    assert_eq!(m1.permissions.kind, MemoryMapEntryPermissionsKind::Private);
    assert_eq!(m1.range.start, 0xaaaad9d30000);
    assert_eq!(m1.range.end, 0xaaaad9d31000);
    assert_eq!(m1.offset, "00000000");
    assert_eq!(m1.dev, "fc:02");
    assert_eq!(m1.inode, "7219570");

    Ok(())
}

#[test]
pub fn when_parse_invalid_memory_map_then_result_is_success() -> Result<(), Box<dyn Error>> {
    let sample = "ZZZZZZZZZZZZ-aaaad9d31000 r-xp 00000000 fc:02 7219570                    /home/cub3d/Documents/pid-stuff/a.out\n";

    let maps = crate::parse_memory_map(sample);
    assert_eq!(maps.is_none(), true);

    Ok(())
}