// A simple ELF file parser in Rust that reads and displays the ELF header information.
// This code focuses on the ELF header structure and its fields
// This is supposed to be simple and educational, definately not optimized for performance, the
// tables and excess enums are proof of that.
//
//
// Resources:
// - https://uclibc.org/docs/elf-64-gen.pdf
// - https://gabi.xinuos.com/elf/b-osabi.html
//
// Author: @joaoofreitas

mod parser;

use std::fs::File;
use std::io::Read;

fn read_elf_header(path: &str) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut header = vec![0; 64];
    file.read_exact(&mut header)?;

    Ok(header)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <elf-file>", args[0]);
        std::process::exit(1);
    }

    println!("Reading ELF file: {}", args[1]);

    let elf_path = &args[1];
    match read_elf_header(elf_path) {
        Ok(header) => {
            let elf_header = parser::ElfHeader::from_bytes(&header);
            elf_header.print();
        }
        Err(e) => {
            eprintln!("Error reading ELF file: {}", e);
            std::process::exit(1);
        }
    }
}
