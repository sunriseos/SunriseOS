//! Types shared by user and kernel

#![no_std]
#![recursion_limit="128"]

// rustc warnings
#![warn(unused)]
#![warn(missing_debug_implementations)]
#![allow(unused_unsafe)]
#![allow(unreachable_code)]
#![allow(dead_code)]
#![cfg_attr(test, allow(unused_imports))]

#![allow(non_upper_case_globals)] // I blame roblabla.

// rustdoc warnings
#![warn(missing_docs)] // hopefully this will soon become deny(missing_docs)
#![deny(intra_doc_link_resolution_failure)]

#[macro_use]
extern crate sunrise_libutils;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate lazy_static;

pub mod error;

use core::fmt;
use static_assertions::assert_eq_size;
use core::mem::size_of;

pub mod process;

/// The state the
enum_with_val! {
    #[derive(Default, Clone, Copy, PartialEq, Eq)]
    pub struct ProcessState(u8) {
        /// Process is freshly created with svcCreateProcess and has not yet been
        /// started.
        Created = 0,
        /// Process has been attached with a debugger before it was started.
        CreatedAttached = 1,
        /// Process has been started.
        Started = 2,
        /// Process has crashed.
        ///
        /// Processes will not enter this state unless they were created with EnableDebug.
        Crashed = 3,
        /// Process is started and has a debugger attached.
        StartedAttached = 4,
        /// Process is currently exiting.
        Exiting = 5,
        /// Process is stopped.
        Exited = 6,
        /// Process has been suspended.
        DebugSuspended = 7
    }
}

bitflags! {
    /// Represents the current state of a memory region: why is it allocated, and
    /// what operations are allowed.
    #[derive(Default)]
    pub struct MemoryState: u32 {
        /// The low 8 bits are used to keep the type.
        // Note that normally, bitflags will refuse to be created with bits it
        // does not recognize. However we can work around this behavior by
        // specifying "compount" bits like the following. Even if we never match
        // it, so long as the bits fall in the range, the bitflag will be
        // considered valid.
        const TY = 0xFF;
        /// Allows the use of `svcSetMemoryPermissions` on this memory region.
        const PERMISSION_CHANGE_ALLOWED = 1 << 8;
        /// Allow writing to read-only segments with `svcWriteDebugProcessMemory`.
        const FORCE_READ_WRITABLE_BY_DEBUG_SYSCALLS = 1 << 9;
        /// Allows sending this region over IPC.
        const IPC_SEND_ALLOWED = 1 << 10;
        /// Allows sending this region over IPC with buffer flag set to 1.
        const NON_DEVICE_IPC_SEND_ALLOWED = 1 << 11;
        /// Allows sending this region over IPC with buffer flag set to 3.
        const NON_SECURE_IPC_SEND_ALLOWED = 1 << 12;
        // Empty
        /// Allows the use of `svcSetProcessMemoryPermission` on this memory region.
        const PROCESS_PERMISSION_CHANGE_ALLOWED = 1 << 14;
        /// Allows remapping this memory region with `svcMapMemory`.
        const MAP_ALLOWED = 1 << 15;
        /// Allows unmapping this memory region through `svcUnmapProcessCodeMemory`.
        const UNMAP_PROCESS_CODE_MEMORY_ALLOWED = 1 << 16;
        /// Allows creating Transfer Memory from this memory region with
        /// `svcCreateTransferMemory`.
        const TRANSFER_MEMORY_ALLOWED = 1 << 17;
        /// Allows using [query_physical_memory] on this memory region.
        ///
        /// [query_physical_memory]: crate::interrupts::syscalls::query_physical_address
        const QUERY_PHYSICAL_ADDRESS_ALLOWED = 1 << 18;
        /// Allows mapping this memory region to a DeviceAddressSpace through either
        /// `svcMapDeviceAddressSpace` or `svcMapDeviceAddressSpaceByForce`.
        const MAP_DEVICE_ALLOWED = 1 << 19;
        /// Allows mapping this memory region to a DeviceAddressSpace through
        /// `svcMapDeviceAddressSpaceAligned`.
        const MAP_DEVICE_ALIGNED_ALLOWED = 1 << 20;
        /// Allows using this memory region as an IPC Command Buffer.
        const IPC_BUFFER_ALLOWED = 1 << 21;
        /// If true, this memory region is reference counted/pool-allocated.
        const IS_REFERENCE_COUNTED = 1 << 22;
        /// Allows mapping this region accross process boundary through
        /// `svcMapProcessMemory`
        const MAP_PROCESS_ALLOWED = 1 << 23;
        /// Allows using the `svcSetMemoryAttribute` syscall on this memory region.
        const ATTRIBUTE_CHANGE_ALLOWED = 1 << 24;
        /// Allows creating a CodeMemory backed by this memory region.
        const CODE_MEMORY_ALLOWED = 1 << 25;

        /// All IPC Buffer Send permissions are allowed by this type.
        const ALL_IPC_SEND_ALLOWED = Self::IPC_SEND_ALLOWED.bits |
            Self::NON_DEVICE_IPC_SEND_ALLOWED.bits |
            Self::NON_SECURE_IPC_SEND_ALLOWED.bits;
        /// This type can use all IOMMU-related permissions (MapDevice allowed,
        /// MapDeviceAligned allowed, and QueryPhysicalAddress allowed).
        const CAN_IOMMU = Self::QUERY_PHYSICAL_ADDRESS_ALLOWED.bits |
            Self::MAP_DEVICE_ALLOWED.bits |
            Self::MAP_DEVICE_ALIGNED_ALLOWED.bits;
    }
}

impl MemoryState {
    /// [MemoryType] this state represents.
    pub fn ty(self) -> MemoryType {
        match self.bits & Self::TY.bits {
            0x00 => MemoryType::Unmapped,
            0x01 => MemoryType::Io,
            0x02 => MemoryType::Normal,
            0x03 => MemoryType::CodeStatic,
            0x04 => MemoryType::CodeMutable,
            0x05 => MemoryType::Heap,
            0x06 => MemoryType::SharedMemory,
            0x07 => MemoryType::Alias,
            0x08 => MemoryType::ModuleCodeStatic,
            0x09 => MemoryType::ModuleCodeMutable,
            0x0A => MemoryType::Ipc,
            0x0B => MemoryType::Stack,
            0x0C => MemoryType::ThreadLocal,
            0x0D => MemoryType::TransferMemoryIsolated,
            0x0E => MemoryType::TransferMemory,
            0x0F => MemoryType::ProcessMemory,
            0x10 => MemoryType::Reserved,
            0x11 => MemoryType::NonSecureIpc,
            0x12 => MemoryType::NonDeviceIpc,
            0x13 => MemoryType::KernelStack,
            0x14 => MemoryType::CodeReadOnly,
            0x15 => MemoryType::CodeWritable,

            // Assume unknown MemoryState are reserved for kernel use. AKA we
            // can't read/write/execute them, nor unmap or do anything on them.
            _    => MemoryType::Reserved,
        }
    }
}

/// The type of this memory area.
///
/// May be used to figure out how the memory area was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    /// Nothing is stored there. Accessing it will page fault. An allocation can
    /// use this region.
    Unmapped = 0,
    /// Mapped by the kernel during process creation, for every IO region in the
    /// NPDM.
    Io = 1,
    /// Mapped by the kernel during process creation, for every Normal region in
    /// the NPDM.
    Normal = 2,
    /// Mapped by the kernel during process creation, at the address and of the
    /// size given by the user in the `CreateProcessInfo`.
    CodeStatic = 3,
    /// Transitioned from CodeStatic in `svcSetProcessMemoryPermission`.
    CodeMutable = 4,
    /// Mapped using `svcSetHeapSize`.
    Heap = 5,
    /// Mapped using `svcMapSharedMemory`.
    SharedMemory = 6,
    /// Mapped by using `svcMapMemory` to remap memory into the Alias region.
    ///
    /// 1.0.0 only!
    Alias = 7,
    /// Mapped using `svcMapProcessCodeMemory`.
    ModuleCodeStatic = 8,
    /// Transitioned from ModuleCodeStatic in `svcSetProcessMemoryPermission`.
    ModuleCodeMutable = 9,
    /// IPC buffers with descriptor flags=0.
    Ipc = 0xA,
    /// Mapped by using `svcMapMemory` to remap memory into the Stack region.
    Stack = 0xB,
    /// Mapped by the kernel during process creation. The TLS region is allocated
    /// there.
    ThreadLocal = 0xC,
    /// Mapped using `svcMapTransferMemory` when the owning process has perm = 0.
    TransferMemoryIsolated = 0xD,
    /// Mapped using `svcMapTransferMemory` when the owning process has perm != 0.
    TransferMemory = 0xE,
    /// Mapped using `svcMapProcessMemory`.
    ProcessMemory = 0xF,
    /// Reserved for kernel use.
    Reserved = 0x10,
    /// IPC buffers with descriptor flags=1.
    NonSecureIpc = 0x11,
    /// IPC buffers with descriptor flags=3.
    NonDeviceIpc = 0x12,
    /// Mapped by the kernel during svcCreateThread. Unused.
    KernelStack = 0x13,
    /// Mapped with `svcControlCodeMemory`.
    CodeReadOnly = 0x14,
    /// Mapped with `svcControlCodeMemory`.
    CodeWritable = 0x15,
}

impl MemoryType {
    /// Get the [MemoryState] associated with a [MemoryType].
    pub fn get_memory_state(self) -> MemoryState {
        match self {
            //
            MemoryType::Unmapped               => MemoryState::from_bits_truncate(0x00000000),
            //
            MemoryType::Io                     => MemoryState::from_bits_truncate(0x00002001),
            // QUERY_PHYSICAL
            MemoryType::Normal                 => MemoryState::from_bits_truncate(0x00042002),
            // DEBUG | IPC_SEND0 | IPC_SEND1 | IPC_SEND3 | PROCESS_PERM_CHANGE | QUERY_PHYSICAL | MAP_DEVICE | MAP_DEVICE_ALIGNED | REFCNT | MAP_PROCESS
            MemoryType::CodeStatic             => MemoryState::from_bits_truncate(0x00DC7E03),
            // PERM_CHANGE | IPC_SEND0 | IPC_SEND1 | IPC_SEND3 | MAP | TRANSFER | QUERY_PHYSICAL | MAP_DEVICE | MAP_DEVICE_ALIGNED | IPC_CMD | REFCNT | MAP_PROCESS | ATTR_CHANGE | CODE_MEM
            MemoryType::CodeMutable            => MemoryState::from_bits_truncate(0x03FEBD04),
            // PERM_CHANGE | IPC_SEND0 | IPC_SEND1 | IPC_SEND3 | MAP | TRANSFER | QUERY_PHYSICAL | MAP_DEVICE | MAP_DEVICE_ALIGNED | IPC_CMD | REFCNT | ATTR_CHANGE | CODE_MEM
            MemoryType::Heap                   => MemoryState::from_bits_truncate(0x037EBD05),
            // REFCNT
            MemoryType::SharedMemory           => MemoryState::from_bits_truncate(0x00402006),
            // PERM_CHANGE | IPC_SEND1 | MAP_DEVICE | REFCNT
            MemoryType::Alias                  => MemoryState::from_bits_truncate(0x00482907),
            // DEBUG | IPC_SEND0 | IPC_SEND1 | IPC_SEND3 | PROCESS_PERM_CHANGE | UNMAP_PROCESS | QUERY_PHYSICAL | MAP_DEVICE | MAP_DEVICE_ALIGNED | REFCNT | MAP_PROCESS
            MemoryType::ModuleCodeStatic       => MemoryState::from_bits_truncate(0x00DD7E08),
            // PERM_CHANGE | IPC_SEND0 | IPC_SEND1 | IPC_SEND3 | MAP | UNMAP_PROCESS | TRANSFER | QUERY_PHYSICAL | MAP_DEVICE | MAP_DEVICE_ALIGNED | IPC_CMD | REFCNT | MAP_PROCESS | ATTR_CHANGE | CODE_MEM
            MemoryType::ModuleCodeMutable      => MemoryState::from_bits_truncate(0x03FFBD09),
            // IPC_SEND0 | IPC_SEND1 | IPC_SEND3 | QUERY_PHYSICAL | MAP_DEVICE | MAP_DEVICE_ALIGNED | REFCNT
            MemoryType::Ipc                    => MemoryState::from_bits_truncate(0x005C3C0A),
            // IPC_SEND0 | IPC_SEND1 | IPC_SEND3 | QUERY_PHYSICAL | MAP_DEVICE | MAP_DEVICE_ALIGNED | REFCNT
            MemoryType::Stack                  => MemoryState::from_bits_truncate(0x005C3C0B),
            // REFCNT
            MemoryType::ThreadLocal            => MemoryState::from_bits_truncate(0x0040200C),
            // IPC_SEND0 | IPC_SEND1 | IPC_SEND3 | QUERY_PHYSICAL | MAP_DEVICE | MAP_DEVICE_ALIGNED | REFCNT | ATTR_CHANGE
            MemoryType::TransferMemoryIsolated => MemoryState::from_bits_truncate(0x015C3C0D),
            // IPC_SEND1 | IPC_SEND3 | QUERY_PHYSICAL | MAP_DEVICE | MAP_DEVICE_ALIGNED | REFCNT
            MemoryType::TransferMemory         => MemoryState::from_bits_truncate(0x005C380E),
            // IPC_SEND1 | IPC_SEND3 | REFCNT
            MemoryType::ProcessMemory          => MemoryState::from_bits_truncate(0x0040380F),
            //
            MemoryType::Reserved               => MemoryState::from_bits_truncate(0x00000010),
            // IPC_SEND1 | IPC_SEND3 | QUERY_PHYSICAL | MAP_DEVICE | MAP_DEVICE_ALIGNED | REFCNT
            MemoryType::NonSecureIpc           => MemoryState::from_bits_truncate(0x005C3811),
            // IPC_SEND1 | QUERY_PHYSICAL | MAP_DEVICE | REFCNT
            MemoryType::NonDeviceIpc           => MemoryState::from_bits_truncate(0x004C2812),
            //
            MemoryType::KernelStack            => MemoryState::from_bits_truncate(0x00002013),
            // DEBUG | REFCNT
            MemoryType::CodeReadOnly           => MemoryState::from_bits_truncate(0x00402214),
            // REFCNT
            MemoryType::CodeWritable           => MemoryState::from_bits_truncate(0x00402015),
        }
    }
}

bitflags! {
    /// Low-level attributes of a memory mapping.
    #[derive(Default)]
    pub struct MemoryAttributes : u32 {
        /// Is mapped in more than one area.
        const BORROWED = 1 << 0;
        /// Is mapped through an IPC request.
        const IPC_MAPPED = 1 << 0;
        /// Is a device mapping.
        const DEVICE_MAPPED = 1 << 2;
        /// Is caching disabled in the MMU.
        const UNCACHED = 1 << 3;
    }
}

bitflags! {
    /// Memory permissions of a memory area.
    #[derive(Default)]
    pub struct MemoryPermissions : u32 {
        /// The area is readable.
        const READABLE = 1 << 0;
        /// The area is writable.
        const WRITABLE = 1 << 1;
        /// The area is executable.
        const EXECUTABLE = 1 << 2;
    }
}

impl MemoryPermissions {
    /// Checks that the permissions as valid - that is, it should be one of
    /// ---, R--, RW- or R-X.
    pub fn check(self) -> Result<(), error::KernelError> {
        // 0x2B is a bitmask where each bit represents an allowed
        // MemoryPermission state: NONE, R, RW, RX.
        // The permission is turned into an index into that bitmask.
        if 1 << self.bits() & 0x2B != 0 {
            Ok(())
        } else {
            Err(error::KernelError::InvalidMemPerms)
        }
    }
}

/// The structure returned by the `query_memory` syscall.
#[repr(C)]
#[derive(Debug, Default)]
pub struct MemoryInfo {
    /// The base address of this memory region.
    ///
    /// This is not the same as the address passed in query_memory. It will
    /// always be lower or equal to it, and will always be page-aligned. It
    /// points to the beggining of the mapping that address falls into.
    pub baseaddr: usize,
    /// The size of this memory region, from the base address.
    pub size: usize,
    /// The type of this mapping.
    ///
    /// Used to figure out how this mapping was created.
    pub memtype: MemoryState,
    /// The attributes of this mapping.
    pub memattr: MemoryAttributes,
    /// The permissions of this mapping.
    pub perms: MemoryPermissions,
    /// Counts how many IPC service requests have an IPC buffer in this mapping.
    pub ipc_ref_count: u32,
    /// Unknown.
    pub device_ref_count: u32,
}

/// Buffer used for Inter Process Communication.
/// Kernel reads, interprets, and copies data from/to it.
///
/// Found in the [TLS] of every thread.
pub type IpcBuffer = [u8; 0x100];

/// Thread Local Storage region.
///
/// The kernel allocates one for every thread, and makes a register point (indirectly) to it
/// so that the userspace can access it at any time.
///
/// * x86_32: Stored at `fs:0x00..fs:0x200`.
/// * x86_64: Stored at `gs:0x00..gs:0x200`.
#[repr(C, align(16))]
pub struct TLS {
    /// Pointer pointing to this TLS region (i.e pointing to itself). Set by the kernel.
    ///
    /// x86 uses the segmentation for accessing the TLS, and it has no way to translate `fs:0x0`
    /// to an address in the flat segmentation model that every other segment uses.
    ///
    /// This pointer serves as a translation.
    pub ptr_self: *mut TLS,
    /// reserved or unknown.
    _reserved0: [u8; 16 - size_of::<*mut TLS>()],
    /// Buffer used for IPC. Kernel reads, interprets, and copies data from/to it.
    pub ipc_command_buffer: IpcBuffer,
    /// reserved or unknown.
    _reserved1: [u8; 0x200 - 16 - size_of::<IpcBuffer>() - size_of::<usize>()],
    /// User controlled pointer to thread context. Not observed by the kernel.
    pub ptr_thread_context: usize,
}

impl fmt::Debug for TLS {
    /// Debug on TLS displays only the address of the IPC command buffer, and `ptr_thread_context`.
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("TLS")
            .field("ipc_command_buffer_address", &(&self.ipc_command_buffer as *const u8))
            .field("ptr_thread_context", &(self.ptr_thread_context as *const u8))
            .finish()
    }
}

assert_eq_size!(TLS, [u8; 0x200]);

macro_rules! syscalls {
    (
        static $byname:ident;
        mod $byid:ident;
        $($name:ident = $id:expr,)*
        ---
        $max_svc_ident:ident = $max_svc_id:expr
    ) => {
        pub mod $byid {
            //! Syscall numbers
            //!
            //! This module contains all the syscalls number <=> string
            //! associations.

            #![allow(missing_docs)]

            $(
                #[allow(non_upper_case_globals)]
                pub const $name: usize = $id;
            )*

            #[allow(non_upper_case_globals)]
            pub const $max_svc_ident: usize = $max_svc_id;
        }
        lazy_static! {
            /// A table associating a syscall name string for every syscall
            /// number.
            pub static ref $byname: [&'static str; $max_svc_id + 1] = {
                let mut arr = ["Unknown"; $max_svc_id + 1];
                $(arr[$id] = stringify!($name);)*
                arr
            };
        }
    }
}

syscalls! {
    static SYSCALL_NAMES;
    mod nr;
    SetHeapSize = 0x01,
    SetMemoryPermission = 0x02,
    SetMemoryAttribute = 0x03,
    MapMemory = 0x04,
    UnmapMemory = 0x05,
    QueryMemory = 0x06,
    ExitProcess = 0x07,
    CreateThread = 0x08,
    StartThread = 0x09,
    ExitThread = 0x0A,
    SleepThread = 0x0B,
    GetThreadPriority = 0x0C,
    SetThreadPriority = 0x0D,
    GetThreadCoreMask = 0x0E,
    SetThreadCoreMask = 0x0F,
    GetCurrentProcessorNumber = 0x10,
    SignalEvent = 0x11,
    ClearEvent = 0x12,
    MapSharedMemory = 0x13,
    UnmapSharedMemory = 0x14,
    CreateTransferMemory = 0x15,
    CloseHandle = 0x16,
    ResetSignal = 0x17,
    WaitSynchronization = 0x18,
    CancelSynchronization = 0x19,
    ArbitrateLock = 0x1A,
    ArbitrateUnlock = 0x1B,
    WaitProcessWideKeyAtomic = 0x1C,
    SignalProcessWideKey = 0x1D,
    GetSystemTick = 0x1E,
    ConnectToNamedPort = 0x1F,
    SendSyncRequestLight = 0x20,
    SendSyncRequest = 0x21,
    SendSyncRequestWithUserBuffer = 0x22,
    SendAsyncRequestWithUserBuffer = 0x23,
    GetProcessId = 0x24,
    GetThreadId = 0x25,
    Break = 0x26,
    OutputDebugString = 0x27,
    ReturnFromException = 0x28,
    GetInfo = 0x29,
    FlushEntireDataCache = 0x2A,
    FlushDataCache = 0x2B,
    MapPhysicalMemory = 0x2C,
    UnmapPhysicalMemory = 0x2D,
    GetFutureThreadInfo = 0x2E,
    GetLastThreadInfo = 0x2F,
    GetResourceLimitLimitValue = 0x30,
    GetResourceLimitCurrentValue = 0x31,
    SetThreadActivity = 0x32,
    GetThreadContext3 = 0x33,
    WaitForAddress = 0x34,
    SignalToAddress = 0x35,
    DumpInfo = 0x3C,
    DumpInfoNew = 0x3D,
    CreateSession = 0x40,
    AcceptSession = 0x41,
    ReplyAndReceiveLight = 0x42,
    ReplyAndReceive = 0x43,
    ReplyAndReceiveWithUserBuffer = 0x44,
    CreateEvent = 0x45,
    MapPhysicalMemoryUnsafe = 0x48,
    UnmapPhysicalMemoryUnsafe = 0x49,
    SetUnsafeLimit = 0x4A,
    CreateCodeMemory = 0x4B,
    ControlCodeMemory = 0x4C,
    SleepSystem = 0x4D,
    ReadWriteRegister = 0x4E,
    SetProcessActivity = 0x4F,
    CreateSharedMemory = 0x50,
    MapTransferMemory = 0x51,
    UnmapTransferMemory = 0x52,
    CreateInterruptEvent = 0x53,
    QueryPhysicalAddress = 0x54,
    QueryIoMapping = 0x55,
    CreateDeviceAddressSpace = 0x56,
    AttachDeviceAddressSpace = 0x57,
    DetachDeviceAddressSpace = 0x58,
    MapDeviceAddressSpaceByForce = 0x59,
    MapDeviceAddressSpaceAligned = 0x5A,
    MapDeviceAddressSpace = 0x5B,
    UnmapDeviceAddressSpace = 0x5C,
    InvalidateProcessDataCache = 0x5D,
    StoreProcessDataCache = 0x5E,
    FlushProcessDataCache = 0x5F,
    DebugActiveProcess = 0x60,
    BreakDebugProcess = 0x61,
    TerminateDebugProcess = 0x62,
    GetDebugEvent = 0x63,
    ContinueDebugEvent = 0x64,
    GetProcessList = 0x65,
    GetThreadList = 0x66,
    GetDebugThreadContext = 0x67,
    SetDebugThreadContext = 0x68,
    QueryDebugProcessMemory = 0x69,
    ReadDebugProcessMemory = 0x6A,
    WriteDebugProcessMemory = 0x6B,
    SetHardwareBreakPoint = 0x6C,
    GetDebugThreadParam = 0x6D,
    GetSystemInfo = 0x6F,
    CreatePort = 0x70,
    ManageNamedPort = 0x71,
    ConnectToPort = 0x72,
    SetProcessMemoryPermission = 0x73,
    MapProcessMemory = 0x74,
    UnmapProcessMemory = 0x75,
    QueryProcessMemory = 0x76,
    MapProcessCodeMemory = 0x77,
    UnmapProcessCodeMemory = 0x78,
    CreateProcess = 0x79,
    StartProcess = 0x7A,
    TerminateProcess = 0x7B,
    GetProcessInfo = 0x7C,
    CreateResourceLimit = 0x7D,
    SetResourceLimitLimitValue = 0x7E,
    CallSecureMonitor = 0x7F,

    // Sunrise extensions
    MapFramebuffer = 0x80,
    StartProcessEntrypoint = 0x81,
    MapMmioRegion = 0x82,
    SetThreadArea = 0x83,

    ---
    // Add SVCs before this line.
    MaxSvc = 0x83
}