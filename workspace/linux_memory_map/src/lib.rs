use std::ops::Range;

#[derive(Debug, Clone)]
pub struct MemoryMap(pub Vec<MemoryMapEntry>);

/// The kind of a given memory map entry
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MemoryMapEntryPermissionsKind {
    Private,
    Shared,
}

impl core::fmt::Display for MemoryMapEntryPermissionsKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Private => write!(f, "private"),
            Self::Shared => write!(f, "shared"),
        }
    }
}

/// The permissions for a given memory map section
#[derive(Copy, Clone, Debug)]
pub struct MemoryMapEntryPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub kind: MemoryMapEntryPermissionsKind,
}

// A single entry in the memory map
#[derive(Clone, Debug)]
pub struct MemoryMapEntry {
    pub range: Range<usize>,
    pub permissions: MemoryMapEntryPermissions,
    pub path: String,
}

/// Get the memory map from /proc/<pid>/maps and parse it
/// Will return none if parsing failed or the file couldn't be opened (generall because the process
/// no longer exists)
pub fn get_memory_map(pid: i32) -> Option<MemoryMap> {
    let content = std::fs::read_to_string(format!("/proc/{}/maps", pid)).ok()?;

    let mut map = Vec::new();
    for line in content.split('\n') {
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split(' ');
        let addr_range = parts.next()?;
        let mut addr_range_parts = addr_range.split('-');
        let addr_range_start = usize::from_str_radix(addr_range_parts.next()?, 16).ok()?;
        let addr_range_end = usize::from_str_radix(addr_range_parts.next()?, 16).ok()?;

        let perms = parts.next()?;
        let _offset = parts.next()?;
        let _dev = parts.next()?;
        let _inode = parts.next()?;
        let pathname = parts.last()?;

        map.push(MemoryMapEntry {
            range: addr_range_start..addr_range_end,
            permissions: MemoryMapEntryPermissions {
                read: perms.contains('r'),
                write: perms.contains('w'),
                execute: perms.contains('x'),
                kind: if perms.contains('p') {
                    MemoryMapEntryPermissionsKind::Private
                } else if perms.contains('s') {
                    MemoryMapEntryPermissionsKind::Shared
                } else {
                    panic!("Unknown permissions: {}", perms);
                },
            },
            path: pathname.to_string(),
        })
    }

    Some(MemoryMap(map))
}
