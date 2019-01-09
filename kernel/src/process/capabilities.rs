//! Process Capability handling
//!
//! The Horizon/NX OS uses a capability scheme for its security system. Each
//! userspace process is created with a list of capabilities. Those capabilities
//! are *not* recursive: each process has its own specific list. The capabilities
//! include which syscall the process is allowed to call, which IRQ it's allowed
//! to listen on, or how many handles it's allowed to create.
//!
//! Those capabilities are inherently arch-specific. For instance, the x86
//! architecture has an additional IOPB field to take care of. To this end, the
//! ProcessCapabilities structure exposed by this module is different from
//! architecture to architecture. Arch-specific methods will be marked as so
//! in their documentation.

use alloc::vec::Vec;
use error::KernelError;
use failure::Backtrace;
use bit_field::BitField;
use bit_field::BitArray;
use core::fmt;

/// Capabilities of a process.
///
/// When a process is created, a list of capabilities is passed along with it,
/// which provides the minimum set of capabilities the process needs to run.
/// Any capability not specified, whether a syscall or an IRQ, is not allowed to
/// be used. Using a forbidden SVC is treated as if the SVC didn't exist.
pub struct ProcessCapabilities {
    /// Bitmask of syscall access controls. Should be accessed through
    /// bit_field::BitArray. A value of 1 means the syscall is accessible, a
    /// value of 0 means the syscall should not be allowed.
    ///
    /// Present on every architecture.
    pub syscall_mask:    [u32; 256 / (8 * 4)],

    /// Bitmask of allowed interrupts. Should be accessed through
    /// bit_field::BitArray. A value of 1 means the process is allowed to create
    /// an IRQEvent for this IRQ number, a value of 0 means creating the event is
    /// not allowed.
    ///
    /// Present on every architecture.
    pub irq_access_mask: [u8; 128],

    /// A vector of readable IO ports.
    ///
    /// When task switching, the IOPB will be changed to take this into account.
    ///
    /// Present on x86 platforms.
    pub ioports:         Vec<u16>,
}

/// Wrapper around a bitfield that only prints the indices of set bits.
struct MaskPrinter<'a, T>(&'a [T]);

impl<'a, T: BitField> fmt::Debug for MaskPrinter<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().enumerate().flat_map(|(idx, v)| {
                (0..T::bit_length())
                    .filter(move |x| v.get_bit(*x))
                    .map(move |x| idx * T::bit_length() + x)
            }))
            .finish()
    }
}

impl fmt::Debug for ProcessCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ProcessCapabilities")
            .field("syscall_mask", &MaskPrinter(&self.syscall_mask))
            .field("irq_access_mask", &MaskPrinter(&self.irq_access_mask))
            .field("ioports", &self.ioports)
            .finish()
    }
}

/// Allowed CPUID and thread priorities.
const KERNEL_FLAGS: u32 = 3;
/// Shifted mask of allowed syscalls.
const SYSCALL_MASK: u32 = 4;
/// Map an IO or physical memory page into process address space.
const MAP_IO_OR_NORMAL_RANGE: u32 = 6;
/// Map a normal page.
const MAP_NORMAL_PAGE: u32 = 7;
/// Allow creating an interrupt for the given IRQ pair.
const INTERRUPT_PAIR: u32 = 11;
/// Type of application (sysmodule, applet, application)
const APPLICATION_TYPE: u32 = 13;
/// Minimum kernel release.
const KERNEL_RELEASE_VERSION: u32 = 14;
/// Max amount of handle for the process.
const HANDLE_TABLE_SIZE: u32 = 15;
/// Flags allowing app to debug or be debugged.
const DEBUG_FLAGS: u32 = 16;

// KFS EXTENSION
/// IOPorts the process is allowed to talk to
const IO_PORTS_ALLOWED: u32 = 10;

const MAX_SVC: usize = ::kfs_libkern::nr::MaxSvc;

/// Mask of kernel capabilities that cannot appear twice in a KCAP array.
const KACS_NO_DUPLICATES: u32 = 0
    | 1 << KERNEL_FLAGS
    | 1 << APPLICATION_TYPE
    | 1 << KERNEL_RELEASE_VERSION
    | 1 << HANDLE_TABLE_SIZE
    | 1 << DEBUG_FLAGS;

impl Default for ProcessCapabilities {
    fn default() -> Self {
        ProcessCapabilities {
            syscall_mask: [0; 256 / (8 * 4)],
            irq_access_mask: [0; 128],
            ioports: Vec::new(),
        }
    }
}

impl ProcessCapabilities {
    /// Parse the kernel capabilities, in the NPDM format. More information on
    /// the format available on [switchbrew].
    ///
    /// # Errors
    ///
    /// INVALID_KCAP:
    /// - Unknown cap_type
    /// - KernelReleaseVersion < 0x80000
    ///
    /// INVALID_COMBINATION:
    /// - Tried to send a duplicate kernel capability that doesn't allow duplicates (bit3, bit13, bit14, bit15, bit16)
    /// - Tried to send two svc masks with the same index
    /// - Lowest CpuId > Highest CpuId in KernelFlags
    /// - LowestPrio > Highest Prio in KernelFlags
    ///
    /// EXCEEDING_MAXIMUM:
    /// - IrqPair with Irq > 0xFF and != 0x3FF
    /// - SvcMask set an interrupt > 0x7F
    ///
    /// INVALID_PROCESSOR_ID:
    /// - KernelFlags cpuid is >= 4
    ///
    /// RESERVED_VALUE:
    /// - HandleTableSize: bit set in the 31..26 range
    /// - DebugFlags: bits set in the 31..19 range
    /// - ApplicationType: bits set in the 31..17 range
    ///
    /// [switchbrew]: http://switchbrew.org/index.php?title=NPDM#Kernel_Access_Control
    pub fn parse_kcaps(kacs: &[u32]) -> Result<ProcessCapabilities, KernelError> {
        let mut capabilities = ProcessCapabilities {
            syscall_mask: [0; 256 / (8 * 4)],
            irq_access_mask: [0; 128],
            ioports: Vec::new(),
        };

        let mut kac_iter = kacs.iter();

        // A bitmask of KACs already found.
        let mut duplicate_kacs = 0;
        let mut duplicate_svc = 0;

        while let Some(kac) = kac_iter.next() {
            let kac_type = (!kac).trailing_zeros();
            if duplicate_kacs.get_bit(kac_type as _) && KACS_NO_DUPLICATES.get_bit(kac_type as _) {
                return Err(KernelError::InvalidCombination {
                    backtrace: Backtrace::new(),
                });
            }
            duplicate_kacs.set_bit(kac_type as _, true);
            match kac_type {
                KERNEL_FLAGS => {
                    let lowest_allowed_prio = kac.get_bits(4..10);
                    let highest_allowed_prio = kac.get_bits(10..16);
                    let lowest_allowed_cpu = kac.get_bits(16..24);
                    let highest_allowed_cpu = kac.get_bits(24..32);
                    if lowest_allowed_prio > highest_allowed_prio {
                        return Err(KernelError::InvalidCombination {
                            backtrace: Backtrace::new(),
                        })
                    }
                    if lowest_allowed_cpu > highest_allowed_cpu {
                        return Err(KernelError::InvalidCombination {
                            backtrace: Backtrace::new(),
                        })
                    }
                },
                SYSCALL_MASK => {
                    let mask = kac.get_bits(5..29);
                    let index = kac.get_bits(29..32);

                    if duplicate_svc.get_bit(index as _) {
                        return Err(KernelError::InvalidCombination {
                            backtrace: Backtrace::new()
                        });
                    }
                    duplicate_svc.set_bit(index as _, true);
                    let index = index as usize * 24;
                    // This cannot overflow: The first 8 bit are guaranteed to be 0.
                    let highest_svc_in_mask = 24 - (mask.leading_zeros() as usize - 8);
                    if index + highest_svc_in_mask > MAX_SVC {
                        return Err(KernelError::ExceedingMaximum {
                            maximum: MAX_SVC as u64,
                            value: (index + highest_svc_in_mask) as u64,
                            backtrace: Backtrace::new()
                        });
                    }
                    capabilities.syscall_mask.set_bits(index..index + 24, mask);
                }
                MAP_IO_OR_NORMAL_RANGE => {
                    let _start_page = kac.get_bits(7..31);
                    let _is_ro = kac.get_bit(31);
                    if let Some(kac) = kac_iter.next() {
                        if (!kac).trailing_zeros() == MAP_IO_OR_NORMAL_RANGE {
                            let _num_pages = kac.get_bits(7..31);
                            let _is_io = kac.get_bit(31);
                            continue;
                        }
                    }
                    return Err(KernelError::InvalidCombination {
                        backtrace: Backtrace::new()
                    });
                },
                MAP_NORMAL_PAGE => {
                    let _page = kac.get_bits(8..32);
                },
                INTERRUPT_PAIR => {
                    let irq0 = kac.get_bits(12..22) as usize;
                    let irq1 = kac.get_bits(22..32) as usize;
                    if irq0 != 0x3FF {
                        if irq0 > 0xFF {
                            return Err(KernelError::ExceedingMaximum {
                                maximum: 0xFF,
                                value: irq0 as u64,
                                backtrace: Backtrace::new(),
                            })
                        }
                        capabilities.irq_access_mask.set_bit(irq0, true);
                    }
                    if irq1 != 0x3FF {
                        if irq0 > 0xFF {
                            return Err(KernelError::ExceedingMaximum {
                                maximum: 0xFF,
                                value: irq1 as u64,
                                backtrace: Backtrace::new(),
                            })
                        }
                        capabilities.irq_access_mask.set_bit(irq1, true);
                    }
                },
                APPLICATION_TYPE => {
                    let _app_type = kac.get_bits(14..17);
                    if kac.get_bits(17..32) != 0 {
                        return Err(KernelError::ReservedValue {
                            backtrace: Backtrace::new()
                        })
                    }
                },
                KERNEL_RELEASE_VERSION => {
                    let _version = kac.get_bits(15..32);
                }
                HANDLE_TABLE_SIZE => {
                    let _handle_table_size = kac.get_bits(16..26);
                    if kac.get_bits(26..32) != 0 {
                        return Err(KernelError::ReservedValue {
                            backtrace: Backtrace::new()
                        })
                    }
                }
                DEBUG_FLAGS => {
                    let _can_be_debugged = kac.get_bit(17);
                    let _can_debug_others = kac.get_bit(18);
                    if kac.get_bits(19..32) != 0 {
                        return Err(KernelError::ReservedValue {
                            backtrace: Backtrace::new()
                        })
                    }
                }
                IO_PORTS_ALLOWED => {
                    let ioport = kac.get_bits(11..27) as u16;
                    if kac.get_bits(27..32) != 0 {
                        return Err(KernelError::ReservedValue {
                            backtrace: Backtrace::new()
                        })
                    }
                    capabilities.ioports.push(ioport);
                }
                _ => {
                    return Err(KernelError::InvalidKernelCaps {
                        kcap: *kac,
                        backtrace: Backtrace::new(),
                    })
                }
            }
        }

        Ok(capabilities)
    }
}
