use gimli::{BaseAddresses, CfaRule, EhFrame, NativeEndian, RegisterRule, UnwindContext, UnwindSection};
use object::{Object, ObjectSection};
use std::collections::HashMap;
use std::fs;

pub struct LoadedBinary {
    eh_frame_data: Vec<u8>,
    text_offset: u64,
    load_base: u64,
    bases: BaseAddresses,
}

pub struct DwarfUnwinder {
    binaries: HashMap<String, LoadedBinary>,
    ctx: UnwindContext<usize>,
}

impl DwarfUnwinder {
    pub fn new() -> Self {
        Self {
            binaries: HashMap::new(),
            ctx: UnwindContext::new(),
        }
    }

    pub fn load_binary(&mut self, path: &str, map_start: u64, map_offset: u64) {
        if self.binaries.contains_key(path) {
            return;
        }

        let Ok(data) = fs::read(path) else { return };
        let Ok(file) = object::File::parse(&*data) else { return };

        let Some(eh_frame_section) = file.section_by_name(".eh_frame") else { return };
        let Ok(eh_frame_data) = eh_frame_section.data() else { return };

        let text_section = file.section_by_name(".text");
        let text_offset = text_section.map(|s| s.address()).unwrap_or(0);

        let load_base = map_start.wrapping_sub(map_offset);

        let bases = BaseAddresses::default()
            .set_eh_frame(eh_frame_section.address().wrapping_add(load_base));

        self.binaries.insert(
            path.to_string(),
            LoadedBinary {
                eh_frame_data: eh_frame_data.to_vec(),
                text_offset,
                load_base,
                bases,
            },
        );
    }

    pub fn unwind(
        &mut self,
        pc: u64,
        sp: u64,
        fp: u64,
        lr: u64,
        stack: &[u8],
        stack_base: u64,
        maps: &[(u64, u64, u64, String)],
    ) -> Vec<u64> {
        let mut frames = vec![];
        let mut pc = pc;
        let mut sp = sp;
        let mut fp = fp;
        let mut lr = lr;

        for _ in 0..128 {
            if pc == 0 {
                break;
            }
            frames.push(pc);

            let Some((map_start, _, map_offset, path)) = find_mapping(pc, maps) else {
                break;
            };

            self.load_binary(path, *map_start, *map_offset);

            let Some(binary) = self.binaries.get(path) else {
                break;
            };

            let adjusted_pc = pc.wrapping_sub(binary.load_base);

            let eh_frame = EhFrame::new(&binary.eh_frame_data, NativeEndian);

            let fde = match eh_frame.fde_for_address(
                &binary.bases,
                pc,
                EhFrame::cie_from_offset,
            ) {
                Ok(fde) => fde,
                Err(_) => {
                    // Try with adjusted PC
                    match eh_frame.fde_for_address(
                        &BaseAddresses::default(),
                        adjusted_pc,
                        EhFrame::cie_from_offset,
                    ) {
                        Ok(fde) => fde,
                        Err(_) => break,
                    }
                }
            };

            let row = match fde.unwind_info_for_address(
                &eh_frame,
                &binary.bases,
                &mut self.ctx,
                pc,
            ) {
                Ok(row) => row,
                Err(_) => {
                    match fde.unwind_info_for_address(
                        &eh_frame,
                        &BaseAddresses::default(),
                        &mut self.ctx,
                        adjusted_pc,
                    ) {
                        Ok(row) => row,
                        Err(_) => break,
                    }
                }
            };

            let cfa = match row.cfa() {
                CfaRule::RegisterAndOffset { register, offset } => {
                    let reg_val = reg_value(*register, sp, fp, lr);
                    (reg_val as i64 + *offset) as u64
                }
                _ => break,
            };

            let ra_register = fde.cie().return_address_register();
            let new_pc = match row.register(ra_register) {
                RegisterRule::Undefined => {
                    if lr != 0 {
                        lr
                    } else {
                        break;
                    }
                }
                RegisterRule::SameValue => reg_value(ra_register, sp, fp, lr),
                RegisterRule::Offset(offset) => {
                    let addr = (cfa as i64 + offset) as u64;
                    match read_u64(addr, stack, stack_base) {
                        Some(v) => v,
                        None => break,
                    }
                }
                RegisterRule::Register(reg) => reg_value(reg, sp, fp, lr),
                _ => break,
            };

            // Update FP if it was saved
            #[cfg(target_arch = "aarch64")]
            let fp_reg = gimli::Register(29);
            #[cfg(target_arch = "x86_64")]
            let fp_reg = gimli::Register(6);
            let new_fp = match row.register(fp_reg) {
                RegisterRule::Offset(offset) => {
                    let addr = (cfa as i64 + offset) as u64;
                    read_u64(addr, stack, stack_base).unwrap_or(fp)
                }
                _ => fp,
            };

            if new_pc == 0 || new_pc == pc {
                break;
            }

            lr = 0;
            fp = new_fp;
            sp = cfa;
            pc = new_pc;
        }

        frames
    }
}

fn find_mapping<'a>(
    addr: u64,
    maps: &'a [(u64, u64, u64, String)],
) -> Option<&'a (u64, u64, u64, String)> {
    maps.iter().find(|(start, end, _, _)| addr >= *start && addr < *end)
}

fn reg_value(reg: gimli::Register, sp: u64, fp: u64, lr: u64) -> u64 {
    #[cfg(target_arch = "aarch64")]
    match reg.0 {
        29 => return fp,
        30 => return lr,
        31 => return sp,
        _ => return 0,
    }

    #[cfg(target_arch = "x86_64")]
    match reg.0 {
        6 => return fp,   // rbp
        7 => return sp,   // rsp
        16 => return lr,  // rip / return address
        _ => return 0,
    }
}

fn read_u64(addr: u64, stack: &[u8], stack_base: u64) -> Option<u64> {
    if addr < stack_base {
        return None;
    }
    let offset = (addr - stack_base) as usize;
    if offset + 8 > stack.len() {
        return None;
    }
    Some(u64::from_ne_bytes(
        stack[offset..offset + 8].try_into().ok()?,
    ))
}
