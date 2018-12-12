//! Types shared by user and kernel

#![no_std]
#![warn(missing_docs)]

#[macro_use]
extern crate kfs_libutils;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate lazy_static;

pub mod error;
 
enum_with_val! {
    /// The type of this memory area.
    ///
    /// May be used to figure out how the memory area was created.
    #[derive(Default, Clone, Copy, PartialEq, Eq)]
    pub struct MemoryType(u32) {
        /// An unmapped memory region. Reading will lead to a data abort.
        Unmapped = 0,
        /// Mapped by kernel capability parsing in `create_process` syscall.
        Io = 0x00002001,
        /// Mapped by kernel capability parsing in `create_process` syscall.
        Normal = 0x00042002,
        /// Mapped during create_process
        CodeStatic = 0x00DC7E03,
        // 1.0.0-3.1.0 0x01FEBD04
        // 4.0.0+
        /// Transition from MemoryType::CodeStatic performed by
        /// `set_process_memory_permission` syscall.
        CodeMutable = 0x03FEBD04,
        // 1.0.0-3.1.0 0x017EBD05
        /// Mapped using `set_heap_size` syscall.
        Heap = 0x037EBD05,
        /// Mapped using `map_shared_memory` syscall.
        SharedMemory = 0x00402006,
        /// Mapped using `map_memory` syscall.
        // 1.0.0 only
        Alias = 0x00482907,
        /// Mapped using `map_process_code_memory` syscall.
        ModuleCodeStatic = 0x00DD7E08,
        // 1.0.0-3.1.0: 0x01FFBD09
        /// Transition from MemoryType::ModuleCodeStatic by
        /// `set_process_memory_permission` syscall.
        ModuleCodeMutable = 0x03FFBD09,
        /// IPC buffers with descriptor flags=0.
        IpcBuffer0 = 0x005C3C0A,
        /// Mapped using `map_memory` syscall.
        Stack = 0x005C3C0B,
        /// Mapped during `create_thread` syscall.
        ThreadLocal = 0x0040200C,
        /// Mapped using `map_transfer_memory` syscall when the owning process
        /// has `perm = 0`.
        TransferMemoryIsolated = 0x015C3C0D,
        /// Mapped using `map_transfer_memory` syscall when the owning process
        /// has `perm != 0`.
        TransferMemory = 0x005C380E,
        /// Mapped using `map_process_memory` syscall.
        ProcessMemory = 0x0040380F,
        /// Reserved memory area, used internally by kernel, should not be
        /// observable.
        Reserved = 0x00000010,
        /// IPC buffers with descriptor flags=1.
        IpcBuffer1 = 0x005C3811,
        /// IPC buffers with descriptor flags=3.
        IpcBuffer3 = 0x004C2812,
        /// Mapped in kernel during `create_thread`. Should not be observable.
        KernelStack = 0x00002013,
        /// Mapped using `control_code_memory` syscall.
        CodeReadOnly = 0x00402214,
        /// Mapped using `control_code_memory` syscall.
        CodeWritable = 0x00402015,
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

/// The structure returned by the `query_memory` structure.
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
    pub memtype: MemoryType,
    /// The attributes of this mapping.
    pub memattr: MemoryAttributes,
    /// The permissions of this mapping.
    pub perms: MemoryPermissions,
    /// Counts how many IPC service requests have an IPC buffer in this mapping.
    pub ipc_ref_count: u32,
    /// Unknown.
    pub device_ref_count: u32,
}

macro_rules! syscalls {
    (
        static $byname:ident;
        mod $byid:ident;
        maxid = $maxid:expr;
        $($name:ident = $id:expr),* $(,)*
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
        }
        lazy_static! {
            /// A table associating a syscall name string for every syscall
            /// number.
            pub static ref $byname: [&'static str; $maxid] = {
                let mut arr = ["Unknown"; $maxid];
                $(arr[$id] = stringify!($name);)*
                arr
            };
        }
    }
}

syscalls! {
    static SYSCALL_NAMES;
    mod nr;
    maxid = 0x82;
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

    MapFramebuffer = 0x80,
    StartProcessEntrypoint = 0x81,
}
