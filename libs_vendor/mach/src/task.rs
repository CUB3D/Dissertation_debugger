//! This module corresponds to `mach/task.defs`.

use kern_return::kern_return_t;
use mach_types::{task_name_t, task_t, thread_act_array_t};
use message::mach_msg_type_number_t;
use port::mach_port_t;
use task_info::{task_flavor_t, task_info_t};
use thread_status::thread_state_flavor_t;
use exception_types::{exception_mask_t, exception_behavior_t};

pub type task_special_port_t = ::libc::c_int;

pub const TASK_KERNEL_PORT: task_special_port_t = 1;
pub const TASK_HOST_PORT: task_special_port_t = 2;
pub const TASK_NAME_PORT: task_special_port_t = 3;
pub const TASK_BOOTSTRAP_PORT: task_special_port_t = 4;

extern "C" {
    pub fn task_resume(target_task: task_t) -> kern_return_t;
    pub fn task_suspend(target_task: task_t) -> kern_return_t;
    pub fn task_get_special_port(
        task: task_t,
        which_port: task_special_port_t,
        special_port: *mut mach_port_t,
    ) -> kern_return_t;
    pub fn task_threads(
        target_task: task_t,
        act_list: *mut thread_act_array_t,
        act_list_cnt: *mut mach_msg_type_number_t,
    ) -> kern_return_t;
    pub fn task_info(
        target_task: task_name_t,
        flavor: task_flavor_t,
        task_info_out: task_info_t,
        task_info_outCnt: *mut mach_msg_type_number_t,
    ) -> kern_return_t;
    pub fn task_set_info(
        target_task: task_t,
        flavor: task_flavor_t,
        task_info_in: task_info_t,
        task_info_inCnt: mach_msg_type_number_t,
    ) -> kern_return_t;
    pub fn task_set_exception_ports(
        task: task_t,
        exception_mask: exception_mask_t,
        new_port: mach_port_t,
        behavior: exception_behavior_t,
        new_flavor: thread_state_flavor_t,
    ) -> kern_return_t;
}
