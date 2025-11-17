#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    pub pid: u32,
}
