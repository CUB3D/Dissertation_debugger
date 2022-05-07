//! Get info about open file descriptors of a process on linux

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::CString;

#[cfg(test)]
pub mod test;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FdLink {
    /// This fd is a socket with the given id
    Socket(String),
    /// This fd is a pipe with the given id
    Pipe(String),
    /// This fd is a path
    Path(String),
    /// Unknown fd type
    Other(String),
}


#[derive(Debug, Clone, Default)]
pub struct FdInfo {
    pub pos: usize,
    pub flags: usize,
    pub mnt_id: usize,
    pub scm_fds: Option<usize>,
    pub eventfd_count: Option<usize>,
    pub eventfd_id: Option<usize>,
    pub lock: Option<String>,
    pub inotify: Option<String>,
    pub link: Option<FdLink>,
}

pub fn parse_fdinfo(content: &str) -> Result<FdInfo, Box<dyn Error>> {
    let mut info = FdInfo::default();

    for line in content.split("\n") {
        if line.trim().is_empty() {
            continue;
        }
        // println!("line = {}", line);
        let key = line.split(":").next().unwrap().trim().to_string();
        let value = line.replace(&format!("{}:", key), "").trim().to_string();

        match key.as_str() {
            "pos" => info.pos = value.parse()?,
            "flags" => info.flags = value.parse()?,
            "mnt_id" => info.mnt_id = value.parse()?,
            "scm_fds" => info.scm_fds = Some(value.parse()?),
            "eventfd-count" => info.eventfd_count = Some(value.parse()?),
            "eventfd-id" => info.eventfd_id = Some(value.parse()?),
            "lock" => info.lock = Some(value.clone()),
            "inotify wd" => info.inotify = Some(value.clone()),
            _ => panic!("Unknown key {}", key)
        }
    }

    Ok(info)
}

pub fn read_fd_link(pid: i32, fd: usize) -> Result<String, Box<dyn Error>> {
    let path = format!("/proc/{}/fd/{}", pid, fd);
    let path_cst = CString::new(path)?;
    let mut output = [0u8; 4096];
    //TODO: actually check if this errors (buffer too small etc)
    let res = unsafe { libc::readlink(path_cst.as_ptr(), &mut output as *mut u8 as *mut _, 4096) };
    assert_ne!(res, -1);
    // Buf isnt null terminated by default
    output[res as usize] = '\0' as u8;
    let output = &output[0..res as usize+1];
    let output = CString::from_vec_with_nul(output.to_vec())?;

   Ok(output.to_str()?.to_string())
}

pub fn parse_fd_link(output: String) -> FdLink {
    let output_en = if output.starts_with("socket:[") {
        FdLink::Socket(output)
    } else if output.starts_with("pipe:[") {
        FdLink::Pipe(output)
    } else {
        FdLink::Other(output)
    };
    output_en
}

pub fn get_fd_info(pid: i32) -> Result<BTreeMap<usize, FdInfo>, Box<dyn Error>> {
    let mut fds = BTreeMap::new();

    for entry in std::fs::read_dir(format!("/proc/{}/fdinfo/", pid))? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let fd: usize = entry.file_name().to_str().unwrap().parse()?;
            // Parse fdinfo key: value pairs
            let content = std::fs::read_to_string(entry.path())?;
            let mut info = parse_fdinfo(&content)?;

            // Readlink all vars
            let output = read_fd_link(pid, fd)?;
            // println!("link = {}", output);
            info.link = Some(parse_fd_link(output));

            fds.insert(fd, info);
        }
    }

    Ok(fds)
}
