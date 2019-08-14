//! Kernel panic
//!
//! ![minor mistake marvin](https://raw.githubusercontent.com/sunriseos/SunriseOS/master/kernel/res/kernel_panic_doc.jpg)

use crate::sync;
use crate::interrupts::UserspaceHardwareContext;
use tinybmp::Bmp;
use crate::interrupts::syscalls::map_framebuffer;
use crate::devices::rs232::SerialLogger;
use crate::i386::gdt::MAIN_TASK;
use crate::scheduler::try_get_current_thread;
use core::fmt::Write;
use crate::i386::registers::eflags::EFlags;

/// Reason for a kernel panic. Must be passed to [kernel_panic].
#[allow(missing_debug_implementations)] // want to display it ? pass it to kernel_panic() !
pub enum PanicOrigin<'a> {
    /// The kernel failed an assertion.
    ///
    /// This is a case when we make a call to `panic!()`, `assert!()`, make an out of bound access, etc.
    KernelAssert {
        /// Formatted string passed to `panic!()`.
        panic_message: core::fmt::Arguments<'a>
    },
    /// CPU Exception occurred while we were in kernel, e.g. page fault.
    ///
    /// This means there's a serious bug in the kernel.
    KernelFault {
        /// Formatted string of the exception name, and optional cpu error code.
        exception_message: core::fmt::Arguments<'a>,
        /// Kernel registers state before exception.
        kernel_hardware_context: UserspaceHardwareContext
    },
    /// Kernel Faulted, and then the fault handler faulted too.
    ///
    /// You fucked up on some quality level.
    ///
    /// Registers state before the second fault can be retrieved from the MAIN_TASK tss.
    DoubleFault,
    /// Userspace exception.
    ///
    /// Normally this isn't a panic, the kernel should kill the faulty process,
    /// display an error message, and keep on going.
    ///
    /// But if the feature panic-on-exception is enabled, we make the kernel panic to help debugging
    /// sessions.
    UserspaceFault {
        /// Formatted string of the exception name, and optional cpu error code.
        exception_message: core::fmt::Arguments<'a>,
        /// Userspace registers state before exception.
        userspace_hardware_context: UserspaceHardwareContext,
    },
}

/// The kernel panic function.
///
/// Executed on a `panic!`, but can also be called directly.
///
/// Will print some useful debugging information, and never return.
///
/// Takes a panic origin, so we can personalize the kernel panic message.
pub fn kernel_panic(panic_origin: &PanicOrigin) -> ! {

    // todo: permanently_disable_interrupts shouldn't be unsafe.
    // body: disabling interrupts doesn't break any safety guidelines, and is perfectly safe as far as rustc is concerned.
    // Disable interrupts forever!
    unsafe { sync::permanently_disable_interrupts(); }
    // Don't deadlock in the logger
    unsafe {
        // safe: All CPUs are halted at this point, and interrupts are stopped.
        //       Any code relying on locked mutex will not run anymore, so unlocking mutexes is fine now.
        SerialLogger.force_unlock();
    }

    // Get the process we were running, and its name. Gonna be quite useful.
    let current_thread = try_get_current_thread();
    let current_process = current_thread.as_ref().map(|t| t.process.clone());
    let current_process_name = current_process.as_ref().map(|p| &p.name);

    //todo: force unlock the KernelMemory lock
    //      and also the process memory lock for userspace stack dumping (only if panic-on-excetpion ?).

    // display the panic header: summary of what happened
    let _ = writeln!(SerialLogger, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\
                                    ! Panic! at the disco");

    match panic_origin {
        PanicOrigin::KernelAssert { panic_message: msg} => {
            let _ = writeln!(SerialLogger, "! {}", msg);
        }
        PanicOrigin::KernelFault { exception_message: msg, ..} => {
            let _ = writeln!(SerialLogger, "! Kernel Fault !\n\
                                            ! {}", msg);
        }
        PanicOrigin::DoubleFault => {
            let _ = writeln!(SerialLogger, "! Double Fault !\n\
                                            ! Good luck.");
        }
        PanicOrigin::UserspaceFault { exception_message: msg, ..} => {
            let _ = writeln!(SerialLogger, "! Userspace exception in {:?}.\n\
                                            ! {}", current_process_name, msg);
        }
    }

    let _ = writeln!(SerialLogger, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

    // Add some nice ascii art to cheer up desperate developers
    match panic_origin {
        PanicOrigin::KernelFault { .. } => {
            let _ = writeln!(SerialLogger, include_str!("../res/kernel_fault.txt"));
        },
        PanicOrigin::DoubleFault { .. } => {
            let _ = writeln!(SerialLogger, include_str!("../res/double_fault.txt"));
        }
        _ => { /* You're not desperate enough */ }
    }

    // Show the name of the process we were running
    // should show thread id in the future.
    let _ = writeln!(SerialLogger, "Process: {:?}", current_process_name);

    // Show hardware context
    match panic_origin {
        PanicOrigin::KernelAssert { .. } => { /* You shouldn't need it */ },
        PanicOrigin::KernelFault { kernel_hardware_context: registers, .. } => {
            let _ = writeln!(SerialLogger, "Kernel registers before fault:\n{}", registers);
        },
        PanicOrigin::UserspaceFault { userspace_hardware_context: registers, .. } => {
            let _ = writeln!(SerialLogger, "Userspace registers before fault:\n{}", registers);
        },
        PanicOrigin::DoubleFault => {
            // Get the Main TSS so I can recover some information about what happened.
            if let Some(tss_main) = MAIN_TASK.try_lock() {
                let _ = writeln!(SerialLogger, "Kernel registers before double fault:\n\
                        EIP={:#010x} CR3={:#010x}\n\
                        EAX={:#010x} EBX={:#010x} ECX={:#010x} EDX={:#010x}\n\
                        ESI={:#010x} EDI={:#010X} ESP={:#010x} EBP={:#010x}\n\
                        EFLAGS={:?}",
                        tss_main.tss.eip, tss_main.tss.cr3,
                        tss_main.tss.eax, tss_main.tss.ebx, tss_main.tss.ecx, tss_main.tss.edx,
                        tss_main.tss.esi, tss_main.tss.edi, tss_main.tss.esp, tss_main.tss.ebp,
                        EFlags::from_bits_truncate(tss_main.tss.eflags));
            } else {
                let _ = writeln!(SerialLogger, "Kernel registers before double fault: Cannot get main TSS, good luck");
            }
        }
    }

    // display the full thread struct
    if let Some(t) = &current_thread {
        let _ = writeln!(SerialLogger, "Current thread: {:#?}", t);
    }

    // display a stack dump

    // Parse the ELF to get the symbol table.
    // We must not fail, so this means a lot of Option checking :/
    use xmas_elf::symbol_table::Entry32;
    use xmas_elf::sections::SectionData;
    use xmas_elf::ElfFile;
    use crate::elf_loader::MappedGrubModule;

    let mapped_kernel_elf = crate::i386::multiboot::try_get_boot_information()
        .and_then(|info| info.module_tags().nth(0))
        .and_then(|module| crate::elf_loader::map_grub_module(module).ok());

    /// Gets the symbol table of a mapped module.
    fn get_symbols<'a>(mapped_kernel_elf: &'a Option<MappedGrubModule<'_>>) -> Option<(&'a ElfFile<'a>, &'a[Entry32])> {
        let module = mapped_kernel_elf.as_ref()?;
        let elf = module.elf.as_ref().ok()?;
        let data = elf.find_section_by_name(".symtab")?
            .get_data(elf).ok()?;
        let st = match data {
            SectionData::SymbolTable32(st) => st,
            _ => return None
        };
        Some((elf, st))
    }

    let elf_and_st = get_symbols(&mapped_kernel_elf);

    if elf_and_st.is_none() {
        let _ = writeln!(SerialLogger, "Panic handler: Failed to get kernel elf symbols");
    }

    // TODO: Kernel Stack dump update
    // BODY: Update the kernel stack dump functions to be compatible the new and improved
    // BODY: kernel panic.
    // BODY:
    // BODY: Now that know the origin (userspace or kernelspace) in the panic, this should
    // BODY: be easy, and we can finally have userspace stack dumps that actually work.
    let stackdump_source = None;

    // Then print the stack
    if let Some(sds) = stackdump_source {
        unsafe {
            // this is unsafe, caller must check safety
            crate::stack::dump_stack(&sds, elf_and_st)
        }
    } else {
        crate::stack::KernelStack::dump_current_stack(elf_and_st)
    }

    // Display the infamous "Blue Screen Of Death"
    display_bsod();

    let _ = writeln!(SerialLogger, "!!!!!!!!!!!!!!!END PANIC!!!!!!!!!!!!!!");

    loop { unsafe { asm!("HLT"); } }
}


/// The "Blue Screen Of Death"
///
/// Stored as an uncompressed BMP, so we don't have to do decompression in the panic handler,
/// and just blit it on the screen instead.
///
/// See [display_bsod].
static BSOD_BMP: &[u8; 1192016] = include_bytes!("../res/bsod.bmp");

/// Display the infamous "Blue Screen Of Death"
///
/// When the kernel panics, we blit an image to the screen to inform the user we have kernel
/// panicked.
///
/// This function attempts to map the framebuffer, and copies [BSOD_BMP] to it.
///
/// It is designed to fail silently if mapping the framebuffer or parsing the BMP failed, as it
/// should only be called from the panic handler, and the last thing we want at that time
/// is more error handling.
///
/// Note that this function will write to the framebuffer with no regards to whether it was already
/// mapped by another process.
/// This is OK since we're panicking, and all processes should be halted by now.
fn display_bsod() {
    if let Ok((fb_addr, fb_width, fb_height, fb_bpp)) = map_framebuffer() {
        let fb = unsafe { core::slice::from_raw_parts_mut(fb_addr as *mut u8, fb_width * fb_height * fb_bpp) };
        if let Ok(bmp) = Bmp::from_slice(BSOD_BMP) {
            let fb_row_len = fb_width * fb_bpp / 8;
            let bmp_row_len = bmp.width() * bmp.bpp() / 8 +
                /* bmp row padded to 4 bytes */ (32 - (bmp.width() * bmp.bpp()) % 32) / 8;
            for (fb_row, bmp_row) in fb.chunks_exact_mut(fb_row_len)
                .zip(bmp.image_data().rchunks_exact(bmp_row_len as usize)) {
                for (fb_px, bmp_px) in fb_row.chunks_exact_mut(fb_bpp / 8)
                    .zip(bmp_row.chunks_exact(bmp.bpp() as usize / 8)) {
                    // bmp has GRB encoding apparently
                    fb_px[0] = bmp_px[1];
                    fb_px[1] = bmp_px[2];
                    fb_px[2] = bmp_px[0];
                    fb_px[3] = 0;
                }
            }
        }
    }
}
