#[macro_use]
extern crate sunrise_libuser as libuser;

fn main() {
    println!("Hello, world!");
}
// TODO: Move this out of here
capabilities!(CAPABILITIES = Capabilities {
    svcs: [
        sunrise_libuser::syscalls::nr::SleepThread,
        sunrise_libuser::syscalls::nr::ExitProcess,
        sunrise_libuser::syscalls::nr::CloseHandle,
        sunrise_libuser::syscalls::nr::WaitSynchronization,
        sunrise_libuser::syscalls::nr::OutputDebugString,
        sunrise_libuser::syscalls::nr::SetThreadArea,

        sunrise_libuser::syscalls::nr::SetHeapSize,
        sunrise_libuser::syscalls::nr::ManageNamedPort,
        sunrise_libuser::syscalls::nr::AcceptSession,
        sunrise_libuser::syscalls::nr::ReplyAndReceiveWithUserBuffer,
        sunrise_libuser::syscalls::nr::CreatePort,
        sunrise_libuser::syscalls::nr::ConnectToPort,
        sunrise_libuser::syscalls::nr::CreateEvent,
        sunrise_libuser::syscalls::nr::SignalEvent,
        sunrise_libuser::syscalls::nr::ClearEvent,
        sunrise_libuser::syscalls::nr::ResetSignal,
    ]
});