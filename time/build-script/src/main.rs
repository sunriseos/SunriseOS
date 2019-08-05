//! Timezone builder script
//!
//! This build script ensure the generation of a timezone archive that is needed by the time service.

use std::env;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::io::SeekFrom;
use std::io::Seek;
use std::fs;
use std::path::Path;

use flate2::read::GzDecoder;
use tar::Archive;

fn main() -> Result<(), Box<std::error::Error>> {
    let mut option = OpenOptions::new();
    option.write(true).read(true).create(true);

    for env in env::vars() {
        println!("{:?}", env);
    }

    // NOTE: this point to the sunrise-time crate directory.
    let crate_directory = env::var("CARGO_MANIFEST_DIR").unwrap();

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("timezone_data.rs");
    let tz_data_path = Path::new(&crate_directory).parent().unwrap().join("external/time/tzdata-2017c.tar.gz");

    let mut tz_data_file = option.open(tz_data_path).unwrap();
    let mut dest_file = File::create(&dest_path).unwrap();

    let tar = GzDecoder::new(tz_data_file);
    let mut archive = Archive::new(tar);

    let mut lines: Vec<String> = Vec::new();
    for file in archive.entries().unwrap() {
        // Make sure there wasn't an I/O error
        let mut file = file.unwrap();

        let header = file.header();

        let path = header.path().unwrap();
        let include_path = Path::new(&out_dir).join(path);

        if header.entry_type().is_dir() {
            fs::create_dir_all(include_path)?;
            continue;
        }

        if !header.entry_type().is_file() {
            continue;
        }


        let path = header.path().unwrap();

        lines.push(format!("    (b\"{}\", include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{}\"))),\n", path.to_string_lossy(), path.to_string_lossy()));
        file.unpack(include_path)?;
    }

    dest_file.write_all(b"/// The internal timezone filesystem content.\n");
    dest_file.write_fmt(format_args!("static TIMEZONE_ARCHIVE: [(&[u8], &[u8]); {}] = [\n", lines.len()))?;

    for line in lines {
        dest_file.write_all(line.as_bytes())?;
    }

    dest_file.write_all(b"];\n")?;

    Ok(())
}
