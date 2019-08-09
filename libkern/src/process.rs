//! Data-structures related to process syscalls.

use core::num::NonZeroU32;
use bitfield::bitfield;
use crate::error::KernelError;

/// Kernel memory pool.
#[repr(u32)]
#[derive(Debug)]
pub enum PoolPartition {
    /// Pool of memory usable by applications. Usually 3GiB.
    Application = 0,
    /// Pool of memory usable by applets. Usually 512MiB.
    Applet,
    /// Pool of memory usable by system modules.
    Sysmodule,
    /// Pool of memory usable by nvidia's driver.
    ///
    /// <Insert nvidia meme here>
    Nvservices
}

impl From<u32> for PoolPartition {
    fn from(partition: u32) -> PoolPartition {
        match partition {
            0 => PoolPartition::Application,
            1 => PoolPartition::Applet,
            2 => PoolPartition::Sysmodule,
            3 => PoolPartition::Nvservices,
            _ => unreachable!("Checked for in check()"),
        }
    }
}

impl From<PoolPartition> for u32 {
    fn from(pool: PoolPartition) -> u32 {
        pool as u32
    }
}

/// Address space type to use when creating a process.
#[repr(u32)]
#[derive(Debug)]
pub enum ProcInfoAddrSpace {
    /// 32-bit address space, spanning from 0x00200000 to 0x007FFFFFFF.
    AS32Bit = 0,
    /// 32-bit address space without the map region.
    AS32BitNoMap,
    /// 36-bit address space, spanning from 0x08000000 to 0x007fffffff.
    AS36Bit,
    /// 39-bit address space, spanning from 0x08000000 to 0x7fffffffff.
    AS39Bit
}

impl From<u32> for ProcInfoAddrSpace {
    fn from(addrspace: u32) -> ProcInfoAddrSpace {
        match addrspace {
            0 => ProcInfoAddrSpace::AS32Bit,
            1 => ProcInfoAddrSpace::AS36Bit,
            2 => ProcInfoAddrSpace::AS32BitNoMap,
            3 => ProcInfoAddrSpace::AS39Bit,
            n => unreachable!("Got unexpected address space number: {}", n),
        }
    }
}

impl From<ProcInfoAddrSpace> for u32 {
    fn from(addrspace: ProcInfoAddrSpace) -> u32 {
        addrspace as u32
    }
}

bitfield! {
    /// Miscelaneous flags.
    pub struct ProcInfoFlags(u32);
    impl Debug;

    /// 64-bit instructions support.
    pub is_64bit, set_64bit: 0;
    /// Address space width of the process.
    pub from into ProcInfoAddrSpace, address_space_type, set_address_space_type: 3, 1;
    /// Whether to signal various conditions (such as exceptions).
    pub is_debug, set_debug: 4;
    /// Enable randomization of the various memory regions (heap, stack, etc...).
    pub is_aslr, set_aslr: 5;
    /// Process is an application. There can only be one application running at
    /// any given time.
    pub is_application, set_application: 6;
    /// unknown.
    pub use_secure_memory, _: 7;
    /// The memory pool to use for this process.
    pub from into PoolPartition, pool_partition, set_pool_partition: 10, 7;
    /// unknown
    pub optimize_memory_allocation, _: 11;
}

impl ProcInfoFlags {
    /// Checks that the ProcInfoFlags doesn't contain any unknown bits.
    pub fn check(&self) -> Result<(), KernelError> {
        if self.0 & !((1 << 12) - 1) != 0 {
            return Err(KernelError::InvalidEnum);
        }

        if self.pool_partition() as u32 > 3 {
            return Err(KernelError::InvalidEnum);
        }

        Ok(())
    }
}

enum_with_val! {
    /// Category of the process.
    #[derive(PartialEq, Eq)]
    pub struct ProcessCategory(u32) {
        /// Regular process created through the userspace loader.
        RegularTitle = 0,
        /// Process loaded by the kernel early during the boot process.
        KernelBuiltin = 1,
    }
}

/// Informations necessary for the create_process syscall.
#[repr(C)]
#[derive(Debug)]
pub struct ProcInfo {
    /// Name of the process (as seen by debuggers).
    pub name: [u8; 12],
    /// Category of the process. Should always be RegularTitle.
    pub process_category: ProcessCategory,
    /// TitleId of the process (as seen by svcGetInfo and debuggers).
    pub title_id: u64,
    /// Address where the main module's code will be loaded. Must be 21-bit
    /// aligned and fall within the "code allowed region", as follows:
    ///
    /// - For 32-bit address space: 0x00200000-0x003FFFFFFF
    /// - For 36-bit address space: 0x08000000-0x007FFFFFFF
    /// - For 39-bit address space: 0x08000000-0x7FFFFFFFFF
    pub code_addr: u64,
    /// Number of pages to allocate for code.
    pub code_num_pages: u32,
    /// Miscelaneous flags
    pub flags: ProcInfoFlags,
    /// Resource limit to use for this process. If None, will use the sysmodule
    /// resource limit and 0x12300000 bytes of memory.
    pub resource_limit_handle: Option<NonZeroU32>,
    /// Maximum amount of kernel memory used to create the process. If 0, then
    /// there is no limit.
    pub system_resource_num_pages: u32,
}
