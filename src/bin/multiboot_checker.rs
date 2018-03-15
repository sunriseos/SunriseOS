// Seriously...
#![feature(iterator_step_by)]

use std::fs::File;
extern crate byteorder;
use byteorder::{ByteOrder, LE};
use std::io::Read;

fn main() {
    let magic = 0xe85250d6;

    let mut f = File::open(std::env::args().nth(1).unwrap()).unwrap();
    let mut file_buf = Vec::new();
    let bytes_read = f.read_to_end(&mut file_buf).unwrap();
    let buf = &file_buf[..std::cmp::min(32768, file_buf.len())];
    if bytes_read < 32 {
        println!("It's too small, can't be a multiboot");
    }

    for i in (0..bytes_read - 16).step_by(8) {
        let header = &buf[i..i + 16];
        if LE::read_u32(&header[0..4]) == magic {
            println!("Found magic at {}", i);
            if LE::read_u32(&header[0..4])
                .wrapping_add(LE::read_u32(&header[4..8]))
                .wrapping_add(LE::read_u32(&header[8..12]))
                .wrapping_add(LE::read_u32(&header[12..16])) != 0
            {
                println!("Wrong checksum!");
            } else {
                println!("Checksum is correct!");
            }
        }
    }

    //    grub_uint32_t *buffer;
    //    grub_ssize_t len;
    //    grub_size_t search_size;
    //    grub_uint32_t *header;
    //    grub_uint32_t magic;
    //    grub_size_t step;
    //
    //
    //    if (type == IS_MULTIBOOT2)
    //      {
    //        search_size = 32768;
    //        magic = grub_cpu_to_le32_compile_time (0xe85250d6);
    //        step = 2;
    //      }
    //    else
    //      {
    //        search_size = 8192;
    //        magic = grub_cpu_to_le32_compile_time (0x1BADB002);
    //        step = 1;
    //      }
    //
    //    buffer = grub_malloc (search_size);
    //    if (!buffer)
    //      break;
    //
    //    len = grub_file_read (file, buffer, search_size);
    //    if (len < 32)
    //      {
    //        grub_free (buffer);
    //        break;
    //      }
    //
    //    /* Look for the multiboot header in the buffer.  The header should
    //       be at least 12 bytes and aligned on a 4-byte boundary.  */
    //    for (header = buffer;
    //         ((char *) header <=
    //          (char *) buffer + len - (type == IS_MULTIBOOT2 ? 16 : 12));
    //         header += step)
    //      {
    //        if (header[0] == magic
    //        && !(grub_le_to_cpu32 (header[0])
    //             + grub_le_to_cpu32 (header[1])
    //             + grub_le_to_cpu32 (header[2])
    //             + (type == IS_MULTIBOOT2
    //            ? grub_le_to_cpu32 (header[3]) : 0)))
    //          {
    //        ret = 1;
    //        break;
    //          }
    //      }
    //
    //    grub_free (buffer);
    //    break;
}
