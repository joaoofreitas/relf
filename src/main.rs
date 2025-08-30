// A simple ELF file parser in Rust that reads and displays the ELF header information.
// This code focuses on the ELF header structure and its fields
// This is supposed to be simple and educational, definitely not optimized for performance.
//
// Resources:
// - https://uclibc.org/docs/elf-64-gen.pdf
// - https://gabi.xinuos.com/elf/b-osabi.html
//
// Author: @joaoofreitas

mod parser;

use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <elf-file>", args[0]);
        process::exit(1);
    }

    println!("Reading ELF file: {}", &args[1]);

    match parser::ElfHeader::from_file(&args[1]) {
        Ok(elf_header) => println!("{}", elf_header),
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
}
