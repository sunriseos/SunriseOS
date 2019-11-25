//! Argument handling
//!
//! When starting a process, Loader will put the program's argument after the
//! first ELF/NSO it loaded. This would usually be rtld for a "normal" program.
//! RTLD will then pass a pointer to the program's main function. The program's
//! arguments are passed completely unparsed. They're literally just a string
//! stored in memory. To take into account the need for parsing, loader will
//! allocate twice as much memory and then some, which should allow the program
//! to copy the strings - adding a \0 when necessary - and then to create the
//! argv pointer array.
//!
//! The memory region allocated by the Loader will be used like this:
//!
//! ```txt
//!    +------------------------+ < Always page-aligned.
//!    |    ProgramArguments    |
//!    |   u32 allocated_size   |
//!    |   u32 arguments_size   |
//!    +------------------------+
//!    |   0x18 Reserved bytes  |
//!    +------------------------+
//!    |      Raw CmdLine       |
//!    |  arguments_size bytes  |
//!    +------------------------+
//!    |    Argument Storage    |
//!    |  arguments_size bytes  |
//!    +------------------------+
//!    | Alignment bytes. Force |
//!    | align to size_of(usize)|
//!    +------------------------+
//!    |      System Argv       |
//!    |  Array of pointers to  |
//!    |    Argument Storage    |
//!    +------------------------+ < allocated_size
//! ```
//!
//! ## SunriseOS Extension: Envp
//!
//! Passing environment variables to a subprogram is necessary for proper
//! execution of the SunriseOS userspace. For instance, it is necessary to pass
//! the current working directory to the subprocess so that executing the
//! following script executes the ls in the right directory.
//!
//! ```bash
//! cd /etc
//! uutils ls
//! ```
//!
//! To achieve this, the same mechanism to pass arguments is used to pass
//! environment variables. The environment variables are passed as a string,
//! after the cmdline, as a `\0`-separated list of VAR_NAME=VAR_VALUE. A
//! variable name may not have an = or a \0 in its name.
//!
//! To separate the cmdline from the environment variables, a `\0` is used. As
//! such, the region allocated by Loader will look like this:
//!
//! ```txt
//!    +------------------------+ < Always page-aligned.
//!    |    ProgramArguments    |
//!    |   u32 allocated_size   |
//!    |   u32 arguments_size   |
//!    +------------------------+
//!    |   0x18 Reserved bytes  |
//!    +------------------------+
//!    |      Raw CmdLine       |
//!    |  arguments_size bytes  |
//!    |                        |
//!    | +--------------------+ |
//!    | |      Arguments     | |
//!    | +--------------------+ |
//!    | |         \0         | |
//!    | +--------------------+ |
//!    | |  Environment vars  | |
//!    | +--------------------+ |
//!    |                        |
//!    +------------------------+
//!    |    Argument Storage    |
//!    |  arguments_size bytes  |
//!    +------------------------+
//!    | Alignment bytes. Force |
//!    | align to size_of(usize)|
//!    +------------------------+
//!    |      System Argv       |
//!    |  Array of pointers to  |
//!    |    Argument Storage    |
//!    +------------------------+
//!    |      System Envp       |
//!    |  Array of pointers to  |
//!    |    environment vars    |
//!    +------------------------+ < allocated_size
//! ```

#[cfg(not(feature = "build-for-std-app"))]
use core::mem::{size_of, align_of};

#[cfg(not(feature = "build-for-std-app"))]
use spin::Once;

#[cfg(not(feature = "build-for-std-app"))]
use sunrise_libutils::{align_up, cast_mut};

#[cfg(not(feature = "build-for-std-app"))]
use crate::syscalls::query_memory;


// If we aren't providing the crt0, we should defer to the CRT0's get_argc()/
// get_argv(). This is especially the case when two versions of the libuser
// exist in the binary simultaneously (such as one included in libstd and one
// used as a direct dependency).
#[cfg(feature = "build-for-std-app")]
extern {
    /// Get the number of arguments in argv.
    #[link_name = "__libuser_get_argc"]
    pub fn argc() -> isize;
    /// Get the argument array. It is guaranteed to have at least `argc()`
    /// elements.
    #[link_name = "__libuser_get_argv"]
    pub fn argv() -> *const *const u8;
    /// Get the environ array. It is guaranteed to end with a NULL element.
    #[link_name = "__libuser_get_envp"]
    pub fn envp() -> *const *const u8;
}

/// Get the number of arguments in argv.
#[cfg(not(feature = "build-for-std-app"))]
#[export_name = "__libuser_get_argc"]
pub extern fn argc() -> isize {
    __libuser_get_args().1
}

/// Get the argument array. It is guaranteed to have at least `argc()`
/// elements.
#[cfg(not(feature = "build-for-std-app"))]
#[export_name = "__libuser_get_argv"]
pub extern fn argv() -> *const *const u8 {
    __libuser_get_args().0 as *const *const u8
}

/// Get the environ array. It is guaranteed to end with a NULL element.
#[cfg(not(feature = "build-for-std-app"))]
#[export_name = "__libuser_get_envp"]
pub extern fn envp() -> *const *const u8 {
    __libuser_get_args().2 as *const *const u8
}

/// Get the arguments and environment. This will parse and setup the arguments
/// and environment the first time it is called - modifying the __argdata__
/// section in the process. This function is safe to call from multiple threads
/// - accesses are synchronized.
///
/// First returned value is the argv, second value is the argc, third value is
/// the envp.
#[cfg(not(feature = "build-for-std-app"))]
#[allow(clippy::cognitive_complexity)]
fn __libuser_get_args() -> (usize, isize, usize) {
    use sunrise_libkern::MemoryPermissions;

    /// Once argdata is parsed, this static contains the pointer to the argument
    /// vector, the size of that vector, and a pointer to the environment
    /// vector.
    static ARGS: Once<(usize, isize, usize)> = Once::new();

    /// Data returned when reading the args fails.
    const NO_ARGS: (usize, isize, usize) = (0, 0, 0);

    extern {
        /// Location where the loader will put the argument data. This symbol is
        /// provided by the linker script.
        static __argdata__: u32;
    }


    *ARGS.call_once(|| {
        let argdata = unsafe {
            &__argdata__ as *const u32 as usize
        };
        assert_eq!(argdata & 0xFFF, 0, "Unaligned __argdata__");

        // First, check we have args at all. __argdata__ is only mapped if
        // loader was given args.
        let (meminfo, _) = match query_memory(argdata) {
            Ok(data) => data,
            Err(_) => return NO_ARGS
        };

        if !meminfo.perms.contains(MemoryPermissions::READABLE | MemoryPermissions::WRITABLE) {
            debug!("Weird args. Perms broken.");
            return NO_ARGS;
        }

        // The args starts with two u32 containing the full size pre-allocated
        // by loader for the args, and the actual arg data sent by loader (in an
        // unparsed form - basically just a cmdline).
        let (argdata_allocsize, argdata_strsize) = unsafe {
            // Safety: Argdata should start at the start of a page, so we've got
            // 0x1000 bytes available at least.
            let data = argdata as *const u32;
            (*data as usize, *data.offset(1) as usize)
        };

        // Do some sanity checks.
        if argdata_allocsize == 0 || argdata_strsize == 0 {
            debug!("Weird args. Allocsize 0 or strsize 0.");
            return NO_ARGS;
        }

        if (argdata - meminfo.baseaddr) + argdata_allocsize > meminfo.size {
            // Args don't fit the memory region. Something properly fucked up.
            // Let's pretend we have none.
            debug!("Weird args. We claim to have {:x} args, but only have {:x} bytes of mem.", argdata_allocsize, meminfo.size);
            return NO_ARGS;
        }

        // Make a big array containing all the data. We'll split it to get all
        // subcomponents afterwards.
        let argdata = unsafe {
            // Safety: We checked above that we have enough memory available.
            // Furthermore, this function should be the only one to access this
            // memory region (all accesses to this memory are gated by the
            // call_once).
            core::slice::from_raw_parts_mut(argdata as *mut u8, argdata_allocsize)
        };

        // The first 0x20 bytes of argdata are reserved. The next
        // argdata_strsize + 1 contain the cmdline. The range after that is
        // where we'll construct our argv, by copying parts of the cmdline, and
        // then building an array of pointer into those copied strings.

        // Skip the ProgramArguments structure.
        if argdata.len() < 0x20 {
            debug!("Weird args. Not big enough for ProgramArguments.");
            return NO_ARGS;
        }
        let (_, argdata) = argdata.split_at_mut(0x20);

        // Recover the cmdline. Why + 1? God only knows. Ask libnx devs.
        if argdata.len() < argdata_strsize + 1 {
            debug!("Weird args. Not big enough for cmdline.");
            return NO_ARGS;
        }
        let (args, argdata) = argdata.split_at_mut(argdata_strsize + 1);

        // Argstorage will contain a bunch of strings copied from the cmdline
        // which we'll use to populate argv afterwards. It should be *at least*
        // the size of argdata_strsize, since in the worst case we'll end up
        // copying the whole thing.
        if argdata.len() < argdata_strsize + 1 {
            debug!("Weird args. Not big enough for 2nd cmdline.");
            return NO_ARGS;
        }
        let (argstorage, argdata) = argdata.split_at_mut(argdata_strsize + 1);

        // Align argstorage to align_of::<usize>(), since __system_argv needs to
        // be ptr-aligned.
        let offset_to_aligned = {
            let argdata_nbr = argdata.as_ptr() as usize;
            align_up(argdata_nbr, align_of::<usize>()) - argdata_nbr
        };
        let (_, argdata) = argdata.split_at_mut(offset_to_aligned);

        // Calculate the max amount of pointers we can store. We need to be able
        // to store at least 2.
        let max_argv = argdata.len() / size_of::<usize>();
        if max_argv < 2 {
            debug!("Weird args. Needs to have space for at least two ptrs.");
            return NO_ARGS;
        }

        let __system_argv: &mut [usize] = unsafe {
            // Safety: The data is valid, (argdata is big enough) and the ptr
            // is properly aligned at this point thanks to the realignment done
            // above.
            cast_mut(argdata)
        };
        let mut __system_argc = 0;

        let mut arg_start = None;
        let mut arg_len = 0;
        let mut quote_flag = false;
        let mut argstorage_idx = 0;
        let mut env_start = None;

        for (argi, item) in args.iter().copied().enumerate() {
            if arg_start.is_none() && item.is_ascii_whitespace() {
                // Skip over ascii whitespace
                continue;
            }

            if item == 0 {
                // We found a '\0', time to start handling environment
                // variables.
                env_start = Some(argi + 1);
                break;
            }

            if let Some(arg_start_idx) = arg_start {
                // We're currently handling an arg.
                // Check if we have reached the end of an argument.
                let end_flag = (quote_flag && item == b'"') || item.is_ascii_whitespace();

                // If we didn't, include the character being processed in the
                // current arg.
                if !end_flag && item != 0 {
                    arg_len += 1;
                }

                if (item == 0 || end_flag) && arg_len != 0 {
                    // If we've reached the end of an argument we copy it to the
                    // argstorage region, and put it in argv.
                    argstorage[argstorage_idx..argstorage_idx + arg_len]
                        .copy_from_slice(&args[arg_start_idx..arg_start_idx + arg_len]);
                    argstorage[argstorage_idx + arg_len] = 0;
                    __system_argv[__system_argc] = argstorage.as_ptr() as usize + argstorage_idx;
                    __system_argc += 1;

                    // Reset all state to and look for the next arg.
                    arg_start = None;
                    quote_flag = false;
                    argstorage_idx += arg_len + 1;
                    arg_len = 0;

                    if __system_argc >= max_argv {
                        break;
                    }
                }
            } else if item == b'"' {
                // Found a new quoted argument.
                arg_start = Some(argi + 1);
                quote_flag = true;
            } else {
                // Found a new argument.
                arg_start = Some(argi);
                arg_len += 1;
            }
        }

        if let Some(arg_start_idx) = arg_start {
            // Handle last argument.
            if __system_argc < max_argv && arg_len != 0 {
                argstorage[argstorage_idx..argstorage_idx + arg_len]
                    .copy_from_slice(&args[arg_start_idx..arg_start_idx + arg_len]);
                argstorage[argstorage_idx + arg_len] = 0;
                __system_argv[__system_argc] = argstorage.as_ptr() as usize + argstorage_idx;
                __system_argc += 1;
            }
        }

        __system_argv[__system_argc] = 0;

        let (__system_argv, __system_envp) = __system_argv.split_at_mut(__system_argc + 1);
        let mut __system_envc = 0;

        if let Some(env_start) = env_start {
            for split in args[env_start..].split(|&v| v == 0) {
                if split.contains(&b'=') {
                    // Handle environment variable.
                    __system_envp[__system_envc] = split.as_ptr() as usize;
                    __system_envc += 1;
                } else {
                    log::error!("Invalid env variable: Does not contain = sign.");
                }
            }
        } else {
            log::debug!("No env variables found");
        }

        __system_envp[__system_envc] = 0;

        #[allow(clippy::cast_possible_wrap)]
        (__system_argv.as_ptr() as usize, __system_argc as isize, __system_envp.as_ptr() as usize)
    })
}