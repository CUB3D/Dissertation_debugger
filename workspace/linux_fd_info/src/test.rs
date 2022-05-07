use crate::FdLink;

#[test]
pub fn when_parse_other_fd_link_then_result_is_other() {
    let f1 = crate::parse_fd_link("/test/".to_string());
    assert_eq!(f1, FdLink::Other("/test/".to_string()));
}

#[test]
pub fn when_parse_socket_fd_link_then_result_is_socket() {
    let f1 = crate::parse_fd_link("socket:[123]".to_string());
    assert_eq!(f1, FdLink::Socket("socket:[123]".to_string()));
}

#[test]
pub fn when_parse_pipe_fd_link_then_result_is_pipe() {
    let f1 = crate::parse_fd_link("pipe:[123]".to_string());
    assert_eq!(f1, FdLink::Pipe("pipe:[123]".to_string()));
}

#[test]
pub fn when_parse_fd_info_then_result_success() {
    let content = "pos:     12\n
    flags:  02\n
    mnt_id: 29\n
    scm_fds:    10\n
    eventfd-count:  11\n
    eventfd-id:     13\n
    lock: asfd\n
    inotify wd: test\n
    ";

    let f1 = crate::parse_fdinfo(content);
    assert_eq!(f1.is_ok(), true);
    let f1 = f1.unwrap();
    assert_eq!(f1.pos, 12);
    assert_eq!(f1.flags, 2);
    assert_eq!(f1.mnt_id, 29);
    assert_eq!(f1.scm_fds, Some(10));
    assert_eq!(f1.eventfd_count, Some(11));
    assert_eq!(f1.eventfd_id, Some(13));
    assert_eq!(f1.lock, Some("asfd".to_string()));
    assert_eq!(f1.inotify, Some("test".to_string()));
    assert_eq!(f1.link, None);
}

#[test]
pub fn when_parse_invalid_fd_info_then_result_fails() {
    let content = "pos:     asdfasdf\n
    flags:  02\n
    mnt_id: 29\n
    ";

    let f1 = crate::parse_fdinfo(content);
    assert_eq!(f1.is_err(), true);
}