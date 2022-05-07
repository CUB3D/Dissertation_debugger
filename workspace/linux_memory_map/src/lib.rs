use std::ops::{Deref, Range};

#[cfg(test)]
pub mod tests;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MemoryMap(pub Vec<MemoryMapEntry>);

impl Deref for MemoryMap {
    type Target = [MemoryMapEntry];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The kind of a given memory map entry
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MemoryMapEntryPermissionsKind {
    /// Private
    Private,
    /// Shared
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
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MemoryMapEntryPermissions {
    /// Is the data readable
    pub read: bool,
    /// Is the data writable
    pub write: bool,
    /// Is the data executable
    pub execute: bool,
    /// The kind of the memory
    pub kind: MemoryMapEntryPermissionsKind,
}

/// A single entry in the memory map
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryMapEntry {
    /// The range of memory
    pub range: Range<usize>,
    /// The permissions of the memory
    pub permissions: MemoryMapEntryPermissions,
    /// The path or comment of the memory
    pub path: String,
    /// Offset
    pub offset: String,
    /// Device
    pub dev: String,
    /// inode
    pub inode: String,
}

/// Parse a memory map string, usually from /proc/<pid>/maps
pub fn parse_memory_map(content: &str) -> Option<MemoryMap> {
    let mut map = Vec::new();
    for line in content.split('\n') {
        if line.is_empty() {
            continue;
        }
        println!("l = {}", line);
        let mut parts = line.split(' ');
        let addr_range = parts.next()?;
        let mut addr_range_parts = addr_range.split('-');
        let addr_range_start = usize::from_str_radix(addr_range_parts.next()?, 16).ok()?;
        let addr_range_end = usize::from_str_radix(addr_range_parts.next()?, 16).ok()?;

        let perms = parts.next()?;
        let offset = parts.next()?;
        let dev = parts.next()?;
        let inode = parts.next()?;
        let pathname = parts.last().unwrap_or("");

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

            offset: offset.to_string(),
            dev: dev.to_string(),
            inode: inode.to_string()
        })
    }

    Some(MemoryMap(map))
}

/// Get the memory map from /proc/<pid>/maps and parse it
/// Will return none if parsing failed or the file couldn't be opened (generall because the process
/// no longer exists)
pub fn get_memory_map(pid: i32) -> Option<MemoryMap> {
    let content = std::fs::read_to_string(format!("/proc/{}/maps", pid)).ok()?;

    parse_memory_map(&content)
}
