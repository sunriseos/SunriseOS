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

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("timezone_data.rs");
    let tz_data_path = Path::new(&out_dir).join("tzcode-latest.tar.gz");

    let mut tz_data_file = option.open(tz_data_path).unwrap();
    let mut dest_file = File::create(&dest_path).unwrap();

    let mut res = reqwest::get("https://thog.eu/sunrise/tzdata-2017c.tar.gz")?;

    // copy the response body directly to stdout
    std::io::copy(&mut res, &mut tz_data_file)?;
    tz_data_file.seek(SeekFrom::Start(0)).unwrap();

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
