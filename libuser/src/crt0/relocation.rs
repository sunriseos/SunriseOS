//! libuser CRT0 relocation
//! Contains stuffs to handle basic dynamic relocation.

// Assembly blob can't get documented, but clippy requires it.
#[allow(clippy::missing_docs_in_private_items)]
mod module_header {
    global_asm!(r#"
    .section .rodata.mod0
    .global module_header
    module_header:
        .ascii "MOD0"
        .int _DYNAMIC - module_header
        .int __bss_start__ - module_header
        .int __bss_end__ - module_header
        .int __eh_frame_hdr_start__ - module_header
        .int __eh_frame_hdr_end__ - module_header
        .int 0 // TODO: runtime-generated module object offset for rtld
    "#);
}

/// The definition of a module header.
/// This is used by RTLD to do dynamic linking.
/// See https://switchbrew.org/wiki/NSO#MOD and https://switchbrew.org/wiki/Rtld
#[repr(C)]
#[derive(Debug)]
pub struct ModuleHeader {
    /// The magic value of the MOD header. "MOD0"
    pub magic: u32,

    /// The offset of the dynamic section relative to ModuleHeader address.
    pub dynamic_off: u32,

    /// The offset of the begining of the bss section relative to ModuleHeader address.
    pub bss_start_off: u32,

    /// The offset of the end of the bss section relative to ModuleHeader address.
    pub bss_end_off: u32,

    /// The offset of the begining of the eh_frame_hdr section relative to ModuleHeader address.
    pub unwind_start_off: u32,

    /// The offset of the end of the eh_frame_hdr section relative to ModuleHeader address.
    pub unwind_end_off: u32,

    /// The offset of the module object that will be used by the rtld.
    /// This offset is relative to ModuleHeader address.
    pub module_object_off: u32
}

impl ModuleHeader {
    /// Module Header Magic.
    pub const MAGIC: u32 = 0x30444F4D;
}

extern "C" {
    /// After relocations have been performed, you can access the module_header in Rust code
    /// through this symbol.
    pub static module_header: ModuleHeader;
}

/// A simple definition of a ELF Dynamic section entry.
#[repr(C)]
#[derive(Debug)]
struct ElfDyn {
    /// The tag of the dynamic entry.
    tag: isize,

    /// The value of the dynamic entry.
    val: usize,
}

/// Marks the end of the _DYNAMIC array.
const DT_NULL: isize = 0;

/// The address of a relocation table.
/// This element requires the DT_RELASZ and DT_RELAENT elements also be present.
/// When relocation is mandatory for a file, either DT_RELA or DT_REL can occur.
const DT_RELA: isize = 7;

/// The total size, in bytes, of the DT_RELA relocation table.
const DT_RELASZ: isize = 8;

/// The size, in bytes, of the DT_RELA relocation entry.
const DT_RELAENT: isize = 9;

/// Indicates that all ElfRela RELATIVE relocations have been concatenated together, and specifies the RELATIVE relocation count. 
const DT_RELACOUNT: isize = 0x6ffffff9;

/// Similar to DT_RELA, except its table has implicit addends.
/// This element requires that the DT_RELSZ and DT_RELENT elements also be present.
const DT_REL: isize = 17;

/// The total size, in bytes, of the DT_REL relocation table.
const DT_RELSZ: isize = 18;

/// The size, in bytes, of the DT_REL relocation entry.
const DT_RELENT: isize = 19;

/// Indicates that all ElfRel RELATIVE relocations have been concatenated together, and specifies the RELATIVE relocation count. 
const DT_RELCOUNT: isize = 0x6ffffffa;

/// Relocation table entry without addend.
#[repr(C)]
struct ElfRel {
    /// The offset of the entry to relocate.
    offset: usize,

    /// The info about of the relocation to perform and its symbol offset.
    info: usize
}

/// Relocation table entry with addend.
#[repr(C)]
struct ElfRela {
    /// The offset of the entry to relocate.
    offset: usize,

    /// The info about of the relocation to perform and its symbol offset.
    info: usize,

    /// Addend.
    addend: isize
}


/// The runtime linker computes the corresponding virtual address by adding the virtual address at which the shared object is loaded to the relative address.
const R_386_RELATIVE: usize = 8;

/// Handle basic relocation. Return a non zero value if failed.
#[cfg(target_os = "sunrise")]
#[no_mangle]
#[allow(clippy::cast_ptr_alignment)]
pub unsafe extern fn relocate_self(aslr_base: *mut u8, module_headr: *const ModuleHeader) -> u32 {
    let module_header_address = module_headr as *const u8;
    let module_headr = &(*module_headr);

    if module_headr.magic != ModuleHeader::MAGIC {
        return 1;
    }

    let mut dynamic = module_header_address.add(module_headr.dynamic_off as usize) as *const ElfDyn;

    let mut rela_offset = None;
    let mut rela_entry_size = 0;
    let mut rela_count = 0;

    let mut rel_offset = None;
    let mut rel_entry_size = 0;
    let mut rel_count = 0;

    while (*dynamic).tag != DT_NULL {
        match (*dynamic).tag {
            DT_RELA => {
                rela_offset = Some((*dynamic).val);
            },
            DT_RELAENT => {
                rela_entry_size = (*dynamic).val;
            },
            DT_REL => {
                rel_offset = Some((*dynamic).val);
            },
            DT_RELENT => {
                rel_entry_size = (*dynamic).val;
            },
            DT_RELACOUNT => {
                rela_count = (*dynamic).val;
            },
            DT_RELCOUNT => {
                rel_count = (*dynamic).val;
            },
            _ => {}
        }
        dynamic = dynamic.offset(1);
    }

    if let Some(rela_offset) = rela_offset {
        if rela_entry_size != core::mem::size_of::<ElfRela>() {
            return 2;
        }
        let rela_base = (aslr_base.add(rela_offset)) as *mut ElfRela;


        for i in 0..rela_count {
            let rela = rela_base.add(i);

            let reloc_type = (*rela).info & 0xff;

            if let R_386_RELATIVE = reloc_type {
                *(aslr_base.add((*rela).offset) as *mut *mut ()) = aslr_base.offset((*rela).addend) as _;
            } else {
                return 4;
            }
        }
    }

    if let Some(rel_offset) = rel_offset {

        if rel_entry_size != core::mem::size_of::<ElfRel>() {
            return 3;
        }

        let rel_base = (aslr_base.add(rel_offset)) as *mut ElfRel;

        for i in 0..rel_count {
            let rel = rel_base.add(i);

            let reloc_type = (*rel).info & 0xff;

            if let R_386_RELATIVE = reloc_type {
                let ptr = aslr_base.add((*rel).offset) as *mut usize;
                *ptr += aslr_base as usize;
            } else {
                return 4;
            }
        }
    }

    0
}
