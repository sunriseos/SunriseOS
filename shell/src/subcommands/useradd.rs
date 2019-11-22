//! Adds a new user to /etc/passwd with the specified username.

use sunrise_libuser::ps2::Keyboard;
use sunrise_libuser::twili::IPipeProxy;
use sunrise_libuser::fs::IFileSystemServiceProxy;
use sunrise_libuser::error::Error;
use core::fmt::Write;
use alloc::vec::Vec;
use alloc::string::String;

/// Help string.
pub static HELP: &str = "useradd <username>: Adds a new user";

/// Adds a new user to /etc/passwd with the specified username.
///
/// The function takes care of prompting for the password in no-echo mode. If
/// an error is returned, then it should be assumed that the user was not added
/// to /etc/passwd.
pub fn main(_stdin: IPipeProxy, mut stdout: IPipeProxy, _stderr: IPipeProxy, args: Vec<String>) -> Result<(), Error> {
    let username = if args.len() < 2 {
        let _ = writeln!(&mut stdout, "usage: useradd <username>");
        return Ok(());
    } else {
        &args[1]
    };

    // Ignore stdin.
    let mut keyboard = Keyboard::new().unwrap();

    let fs_proxy = IFileSystemServiceProxy::raw_new().unwrap();
    let filesystem = fs_proxy.open_disk_partition(0, 0).unwrap();

    let res = (|| -> Result<(), Error> {
        let _ = writeln!(&mut stdout, "Password: ");
        let password = crate::get_next_line_no_echo(&mut keyboard);
        let password = password.trim_end_matches('\n');

        let hash = sha1::Sha1::from(&password).digest().bytes();

        let mut ipc_path = [0x0; 0x300];
        ipc_path[..b"/etc/passwd".len()].copy_from_slice(b"/etc/passwd");

        let _ = filesystem.create_file(0, 0, &ipc_path);
        let file = filesystem.open_file(0b111, &ipc_path)?;
        let size = file.get_size()?;

        let mut newline = String::from(username);
        newline.push(' ');
        newline += &hex::encode(&hash);
        newline.push('\n');

        file.write(0, size, newline.len() as _, newline.as_bytes())?;
        Ok(())
    })();

    if let Err(err) = res {
        let _ = writeln!(&mut stdout, "Failed to add user: {:?}", err);
        Ok(())
    } else {
        Ok(())
    }
}