//! Show a gif in a new window
//!
//! Show the provided gif (passed as first argument) in a new window. The window
//! will get closed when a key is pressed.

use core::fmt::Write;
use alloc::string::String;
use alloc::vec::Vec;

use sunrise_libuser::ps2::Keyboard;
use sunrise_libuser::twili::IPipeProxy;
use sunrise_libuser::fs::IFileSystemServiceProxy;
use sunrise_libuser::window::{Color, Window};
use sunrise_libuser::error::Error;

/// Help string.
pub static HELP: &str = "showgif <path>: Display the provided gif";

/// Shows a GIF in a new window, blocking the caller. When a key is pressed, the
/// window is closed and control is given back to the caller.
pub fn main(_stdin: IPipeProxy, mut stdout: IPipeProxy, _stderr: IPipeProxy, args: Vec<String>) -> Result<(), Error> {
    let gif_path = match args.get(1) {
        Some(v) => v,
        None => {
            let _ = writeln!(&mut stdout, "Usage: showgif <path>");
            return Ok(())
        },
    };

    let fs_proxy = IFileSystemServiceProxy::raw_new().unwrap();
    let filesystem = fs_proxy.open_disk_partition(0, 0).unwrap();

    let gif_path = crate::get_path_relative_to_current_directory(gif_path);
    let mut ipc_path = [0x0; 0x300];
    ipc_path[..gif_path.len()].copy_from_slice(gif_path.as_bytes());
    let file = filesystem.open_file(0b111, &ipc_path)?;
    let size = file.get_size()?;

    let mut filebuf = vec![0; size as usize];
    let read = file.read(0, 0, filebuf.len() as u64, &mut filebuf)?;
    let filebuf = &filebuf[..read as usize];

    let mut keyboard = Keyboard::new().unwrap();
    let mut reader = gif::Decoder::new(&filebuf[..]).read_info().unwrap();
    let mut window = Window::new(0, 0, u32::from(reader.width()), u32::from(reader.height())).unwrap();

    let mut buf = Vec::new();

    loop {
        {
            let end = reader.next_frame_info().unwrap().is_none();
            if end {
                reader = gif::Decoder::new(&filebuf[..]).read_info().unwrap();
                let _ = reader.next_frame_info().unwrap().unwrap();
            }
        }
        buf.resize(reader.buffer_size(), 0);
        // simulate read into buffer
        reader.read_into_buffer(&mut buf[..]).unwrap();
        for y in 0..(reader.height() as usize) {
            for x in 0..(reader.width() as usize) {
                let frame_coord = (y * reader.width() as usize + x) * 4;
                window.write_px_at(x, y, Color::rgb(buf[frame_coord], buf[frame_coord + 1], buf[frame_coord + 2]));
            }
        }
        window.draw().unwrap();
        if keyboard.try_read_key().is_some() {
            return Ok(());
        }
    }
}