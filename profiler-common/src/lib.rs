#![no_std]

pub const STACK_DUMP_SIZE: usize = 4096;
pub const MAX_CPI_DEPTH: usize = 5;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProgramState {
    pub in_sbf: u32,
    pub depth: u32,
    pub program_id: [u8; 32],
    pub ids: [[u8; 32]; MAX_CPI_DEPTH],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    pub pid: u32,
    pub _pad: u32,
    pub cpu_cycles: u64,
    pub pc: u64,
    pub sp: u64,
    pub fp: u64,
    pub lr: u64,
    pub program_id: [u8; 32],
    pub stack_size: u64,
    pub stack_data: [u8; STACK_DUMP_SIZE],
}
