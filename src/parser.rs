// ELF Class constants
const ELF_CLASS_TABLE: [(u8, &str); 3] = [
    (0, "Invalid class"),
    (1, "32-bit objects"),
    (2, "64-bit objects"),
];

#[derive(Debug, Clone, Copy)]
enum IdentClass {
    ELFCLASS32 = 1,
    ELFCLASS64 = 2,
}

// ELF Data encoding constants
const ELF_DATA_TABLE: [(u8, &str); 3] = [
    (0, "Invalid data encoding"),
    (1, "Little-endian"),
    (2, "Big-endian"),
];

#[derive(Debug, Clone, Copy)]
enum IdentData {
    ELFDATA2LSB = 1,
    ELFDATA2MSB = 2,
}

// ELF Version constants
const ELF_VERSION_TABLE: [(u8, &str); 2] = [
    (0, "Invalid version"),
    (1, "Current version"),
];

#[derive(Debug, Clone, Copy)]
enum IdentVersion {
    EvNone = 0,
    EvCurrent = 1,
}

// ELF OS/ABI constants
const ELF_OSABI_TABLE: [(u8, &str); 20] = [
    (0, "No extensions or unspecified"),
    (1, "HP-UX"),
    (2, "NetBSD"),
    (3, "GNU"),
    (4, "Reserved"),
    (5, "Reserved"),
    (6, "Solaris"),
    (7, "AIX"),
    (8, "IRIX"),
    (9, "FreeBSD"),
    (10, "Tru64"),
    (11, "Novell Modesto"),
    (12, "OpenBSD"),
    (13, "OpenVMS"),
    (14, "NonStop Kernel"),
    (15, "AROS"),
    (16, "FenixOS"),
    (17, "CloudABI"),
    (18, "Stratus Technologies OpenVOS"),
    (255, "Standalone (embedded) application"),
];

#[derive(Debug, Clone, Copy)]
enum IdentOSABI {
    NONE = 0,
    HPUX = 1,
    NETBSD = 2,
    GNU = 3,
    SOLARIS = 6,
    AIX = 7,
    IRIX = 8,
    FREEBSD = 9,
    TRU64 = 10,
    MODESTO = 11,
    OPENBSD = 12,
    OPENVMS = 13,
    NSK = 14,
    AROS = 15,
    FENIXOS = 16,
    CLOUDABI = 17,
    OPENVOS = 18,
    STANDALONE = 255,
}

// ELF Identification structure
struct EIdent {
    magic: [u8; 4],
    class: IdentClass,
    data: IdentData,
    version: IdentVersion,
    os_abi: IdentOSABI,
    abi_version: u8,
}

impl EIdent {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() < 16 {
            panic!("Invalid ELF ident size");
        }

        // Check magic number
        if bytes[0..4] != [0x7f, b'E', b'L', b'F'] {
            panic!("Invalid ELF magic number");
        }

        let mut magic = [0; 4];
        magic.copy_from_slice(&bytes[0..4]);

        let class = match bytes[4] {
            1 => IdentClass::ELFCLASS32,
            2 => IdentClass::ELFCLASS64,
            _ => panic!("Invalid ELF class"),
        };

        let data = match bytes[5] {
            1 => IdentData::ELFDATA2LSB,
            2 => IdentData::ELFDATA2MSB,
            _ => panic!("Invalid ELF data encoding"),
        };

        let version = match bytes[6] {
            0 => IdentVersion::EvNone,
            1 => IdentVersion::EvCurrent,
            _ => panic!("Invalid ELF version"),
        };

        let os_abi = match bytes[7] {
            0 => IdentOSABI::NONE,
            1 => IdentOSABI::HPUX,
            2 => IdentOSABI::NETBSD,
            3 => IdentOSABI::GNU,
            4 => todo!("Reserved OSABI"),
            5 => todo!("Reserved OSABI"),
            6 => IdentOSABI::SOLARIS,
            7 => IdentOSABI::AIX,
            8 => IdentOSABI::IRIX,
            9 => IdentOSABI::FREEBSD,
            10 => IdentOSABI::TRU64,
            11 => IdentOSABI::MODESTO,
            12 => IdentOSABI::OPENBSD,
            13 => IdentOSABI::OPENVMS,
            14 => IdentOSABI::NSK,
            15 => IdentOSABI::AROS,
            16 => IdentOSABI::FENIXOS,
            17 => IdentOSABI::CLOUDABI,
            18 => IdentOSABI::OPENVOS,
            19_u8..=254_u8 => todo!("Reserved OSABI"),
            255 => IdentOSABI::STANDALONE,
        };

        let abi_version = bytes[8];

        EIdent {
            magic,
            class,
            data,
            version,
            os_abi,
            abi_version,
        }
    }

    pub fn print(&self) {
        println!("ELF Identification:");
        println!("  Magic: {:x?}", self.magic);
        println!("  Class: {:?}", ELF_CLASS_TABLE[self.class as usize]);
        println!("  Data: {:?}", ELF_DATA_TABLE[self.data as usize]);
        println!("  Version: {:?}", ELF_VERSION_TABLE[self.version as usize]);
        println!("  OS/ABI: {:?}", ELF_OSABI_TABLE[self.os_abi as usize]);
        println!("  ABI Version: {}", self.abi_version);
    }
}

// ELF Type constants
const ELF_TYPE_TABLE: [(u16, &str); 7] = [
    (0, "No file type"),
    (1, "Relocatable file"),
    (2, "Executable file"),
    (3, "Shared object file"),
    (4, "Core file"),
    (0xff00, "Processor-specific"),
    (0xffff, "Processor-specific"),
];

#[derive(Debug, Clone, Copy)]
enum ElfType {
    EtNone = 0,
    EtRel = 1,
    EtExec = 2,
    EtDyn = 3,
    EtCore = 4,
    EtLoProc = 0xff00,
    EtHiProc = 0xffff,
}

// ELF Machine constants
const ELF_MACHINE_TABLE: [(u16, &str); 21] = [
    (0, "No machine"),
    (1, "AT&T WE 32100"),
    (2, "SPARC"),
    (3, "Intel 80386"),
    (4, "Motorola 68000"),
    (5, "Motorola 88000"),
    (7, "Intel 80860"),
    (8, "MIPS I Architecture"),
    (9, "IBM System/370 Processor"),
    (10, "MIPS RS3000 Little-endian"),
    (15, "Hewlett-Packard PA-RISC"),
    (17, "Fujitsu VPP500"),
    (18, "Enhanced instruction set SPARC"),
    (19, "Intel 80960"),
    (20, "PowerPC"),
    (21, "PowerPC64"),
    (22, "IBM System/390 Processor"),
    (183, "ARM AARCH64"),
    (243, "RISC-V"),
    (0xff00, "Processor-specific"),
    (0xffff, "Processor-specific"),
];

#[derive(Debug, Clone, Copy)]
enum ElfMachine {
    EmNone = 0,
    EmM32 = 1,
    EmSparc = 2,
    Em386 = 3,
    Em68k = 4,
    Em88k = 5,
    Em860 = 7,
    EmMips = 8,
    EmS370 = 9,
    EmMipsRs3Le = 10,
    EmParisc = 15,
    EmVpp500 = 17,
    EmSparc32Plus = 18,
    Em960 = 19,
    EmPpc = 20,
    EmPpc64 = 21,
    EmS390 = 22,
    EmAarch64 = 183,
    EmRiscv = 243,
    EmLoProc = 0xff00,
    EmHiProc = 0xffff,
}

// ELF Version constants
const ELF_VERSION_ENUM: [(u32, &str); 2] = [
    (0, "Invalid version"),
    (1, "Current version"),
];

#[derive(Debug, Clone, Copy)]
enum ElfVersion {
    EvNone = 0,
    EvCurrent = 1,
}

// ELF Header structure
pub struct ElfHeader {
    ident: EIdent,
    e_type: ElfType,
    machine: ElfMachine,
    version: ElfVersion,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
}

impl ElfHeader {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() < 64 {
            panic!("Invalid ELF header size");
        }

        let ident = EIdent::from_bytes(&bytes[0..16]);

        let e_type = match u16::from_le_bytes([bytes[16], bytes[17]]) {
            0 => ElfType::EtNone,
            1 => ElfType::EtRel,
            2 => ElfType::EtExec,
            3 => ElfType::EtDyn,
            4 => ElfType::EtCore,
            0xff00 => ElfType::EtLoProc,
            0xffff => ElfType::EtHiProc,
            _ => panic!("Invalid ELF type"),
        };

        let machine = match u16::from_le_bytes([bytes[18], bytes[19]]) {
            0 => ElfMachine::EmNone,
            1 => ElfMachine::EmM32,
            2 => ElfMachine::EmSparc,
            3 => ElfMachine::Em386,
            4 => ElfMachine::Em68k,
            5 => ElfMachine::Em88k,
            7 => ElfMachine::Em860,
            8 => ElfMachine::EmMips,
            9 => ElfMachine::EmS370,
            10 => ElfMachine::EmMipsRs3Le,
            15 => ElfMachine::EmParisc,
            17 => ElfMachine::EmVpp500,
            18 => ElfMachine::EmSparc32Plus,
            19 => ElfMachine::Em960,
            20 => ElfMachine::EmPpc,
            21 => ElfMachine::EmPpc64,
            22 => ElfMachine::EmS390,
            183 => ElfMachine::EmAarch64,
            243 => ElfMachine::EmRiscv,
            0xff00 => ElfMachine::EmLoProc,
            0xffff => ElfMachine::EmHiProc,
            _ => panic!("Invalid ELF machine"),
        };

        let version = match u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]) {
            0 => ElfVersion::EvNone,
            1 => ElfVersion::EvCurrent,
            _ => panic!("Invalid ELF version"),
        };

        let entry = u64::from_le_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]);

        let phoff = u64::from_le_bytes([
            bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37], bytes[38], bytes[39],
        ]);

        let shoff = u64::from_le_bytes([
            bytes[40], bytes[41], bytes[42], bytes[43], bytes[44], bytes[45], bytes[46], bytes[47],
        ]);

        let flags = u32::from_le_bytes([bytes[48], bytes[49], bytes[50], bytes[51]]);
        let ehsize = u16::from_le_bytes([bytes[52], bytes[53]]);
        let phentsize = u16::from_le_bytes([bytes[54], bytes[55]]);
        let phnum = u16::from_le_bytes([bytes[56], bytes[57]]);
        let shentsize = u16::from_le_bytes([bytes[58], bytes[59]]);
        let shnum = u16::from_le_bytes([bytes[60], bytes[61]]);
        let shstrndx = u16::from_le_bytes([bytes[62], bytes[63]]);

        ElfHeader {
            ident,
            e_type,
            machine,
            version,
            entry,
            phoff,
            shoff,
            flags,
            ehsize,
            phentsize,
            phnum,
            shentsize,
            shnum,
            shstrndx,
        }
    }

    pub fn print(&self) {
        self.ident.print();
        println!("ELF Type: {:?}", ELF_TYPE_TABLE[self.e_type as usize]);
        println!("Machine: {:?}", ELF_MACHINE_TABLE[self.machine as usize]);
        println!("Version: {:?}", ELF_VERSION_ENUM[self.version as usize]);
        println!("Entry point address: 0x{:x}", self.entry);
        println!("Start of program headers: {} (bytes into file)", self.phoff);
        println!("Start of section headers: {} (bytes into file)", self.shoff);
        println!("Flags: 0x{:x}", self.flags);
        println!("Size of this header: {} (bytes)", self.ehsize);
        println!("Size of program headers: {} (bytes)", self.phentsize);
        println!("Number of program headers: {}", self.phnum);
        println!("Size of section headers: {} (bytes)", self.shentsize);
        println!("Number of section headers: {}", self.shnum);
        println!("Section header string table index: {}", self.shstrndx);
    }
}
