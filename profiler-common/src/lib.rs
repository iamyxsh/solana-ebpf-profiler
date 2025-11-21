#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    pub pid: u32,
    pub stack_id: i64,
    pub cpu_cycles: u64,
}
