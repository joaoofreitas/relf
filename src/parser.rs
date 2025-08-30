use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug)]
pub enum ElfParseError {
    InvalidSize,
    InvalidMagic,
    InvalidClass,
    InvalidData,
    InvalidVersion,
    InvalidOsAbi,
    InvalidType,
    InvalidMachine,
    ReservedOsAbi,
    IoError(std::io::Error),
}

impl Display for ElfParseError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            ElfParseError::InvalidSize => write!(f, "Invalid ELF header size"),
            ElfParseError::InvalidMagic => write!(f, "Invalid ELF magic number"),
            ElfParseError::InvalidClass => write!(f, "Invalid ELF class"),
            ElfParseError::InvalidData => write!(f, "Invalid ELF data encoding"),
            ElfParseError::InvalidVersion => write!(f, "Invalid ELF version"),
            ElfParseError::InvalidOsAbi => write!(f, "Invalid ELF OS/ABI"),
            ElfParseError::InvalidType => write!(f, "Invalid ELF type"),
            ElfParseError::InvalidMachine => write!(f, "Invalid ELF machine"),
            ElfParseError::ReservedOsAbi => write!(f, "Reserved OS/ABI value"),
            ElfParseError::IoError(e) => write!(f, "IO Error: {}", e),
        }
    }
}

impl std::error::Error for ElfParseError {}

#[derive(Debug, Clone, Copy)]
enum IdentClass {
    ELFCLASS32 = 1,
    ELFCLASS64 = 2,
}

impl Display for IdentClass {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            IdentClass::ELFCLASS32 => write!(f, "32-bit objects"),
            IdentClass::ELFCLASS64 => write!(f, "64-bit objects"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum IdentData {
    ELFDATA2LSB = 1,
    ELFDATA2MSB = 2,
}

impl Display for IdentData {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            IdentData::ELFDATA2LSB => write!(f, "Little-endian"),
            IdentData::ELFDATA2MSB => write!(f, "Big-endian"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum IdentVersion {
    EvNone = 0,
    EvCurrent = 1,
}

impl Display for IdentVersion {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            IdentVersion::EvNone => write!(f, "Invalid version"),
            IdentVersion::EvCurrent => write!(f, "Current version"),
        }
    }
}

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

impl Display for IdentOSABI {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            IdentOSABI::NONE => write!(f, "No extensions or unspecified"),
            IdentOSABI::HPUX => write!(f, "HP-UX"),
            IdentOSABI::NETBSD => write!(f, "NetBSD"),
            IdentOSABI::GNU => write!(f, "GNU"),
            IdentOSABI::SOLARIS => write!(f, "Solaris"),
            IdentOSABI::AIX => write!(f, "AIX"),
            IdentOSABI::IRIX => write!(f, "IRIX"),
            IdentOSABI::FREEBSD => write!(f, "FreeBSD"),
            IdentOSABI::TRU64 => write!(f, "Tru64"),
            IdentOSABI::MODESTO => write!(f, "Novell Modesto"),
            IdentOSABI::OPENBSD => write!(f, "OpenBSD"),
            IdentOSABI::OPENVMS => write!(f, "OpenVMS"),
            IdentOSABI::NSK => write!(f, "NonStop Kernel"),
            IdentOSABI::AROS => write!(f, "AROS"),
            IdentOSABI::FENIXOS => write!(f, "FenixOS"),
            IdentOSABI::CLOUDABI => write!(f, "CloudABI"),
            IdentOSABI::OPENVOS => write!(f, "Stratus Technologies OpenVOS"),
            IdentOSABI::STANDALONE => write!(f, "Standalone (embedded) application"),
        }
    }
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
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ElfParseError> {
        if bytes.len() < 16 {
            return Err(ElfParseError::InvalidSize);
        }

        // Check magic number
        if bytes[0..4] != [0x7f, b'E', b'L', b'F'] {
            return Err(ElfParseError::InvalidMagic);
        }

        let mut magic = [0; 4];
        magic.copy_from_slice(&bytes[0..4]);

        let class = match bytes[4] {
            1 => IdentClass::ELFCLASS32,
            2 => IdentClass::ELFCLASS64,
            _ => return Err(ElfParseError::InvalidClass),
        };

        let data = match bytes[5] {
            1 => IdentData::ELFDATA2LSB,
            2 => IdentData::ELFDATA2MSB,
            _ => return Err(ElfParseError::InvalidData),
        };

        let version = match bytes[6] {
            0 => IdentVersion::EvNone,
            1 => IdentVersion::EvCurrent,
            _ => return Err(ElfParseError::InvalidVersion),
        };

        let os_abi = match bytes[7] {
            0 => IdentOSABI::NONE,
            1 => IdentOSABI::HPUX,
            2 => IdentOSABI::NETBSD,
            3 => IdentOSABI::GNU,
            4..=5 => return Err(ElfParseError::ReservedOsAbi),
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
            19..=254 => return Err(ElfParseError::ReservedOsAbi),
            255 => IdentOSABI::STANDALONE,
        };

        let abi_version = bytes[8];

        Ok(EIdent {
            magic,
            class,
            data,
            version,
            os_abi,
            abi_version,
        })
    }
}

impl Display for EIdent {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        writeln!(f, "ELF Identification:")?;
        writeln!(f, "  Magic: {:x?}", self.magic)?;
        writeln!(f, "  Class: {}", self.class)?;
        writeln!(f, "  Data: {}", self.data)?;
        writeln!(f, "  Version: {}", self.version)?;
        writeln!(f, "  OS/ABI: {}", self.os_abi)?;
        write!(f, "  ABI Version: {}", self.abi_version)
    }
}

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

impl Display for ElfType {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            ElfType::EtNone => write!(f, "No file type"),
            ElfType::EtRel => write!(f, "Relocatable file"),
            ElfType::EtExec => write!(f, "Executable file"),
            ElfType::EtDyn => write!(f, "Shared object file"),
            ElfType::EtCore => write!(f, "Core file"),
            ElfType::EtLoProc => write!(f, "Processor-specific (low)"),
            ElfType::EtHiProc => write!(f, "Processor-specific (high)"),
        }
    }
}

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
    EmX8664 = 62,
    EmAarch64 = 183,
    EmRiscv = 243,
    EmLoProc = 0xff00,
    EmHiProc = 0xffff,
}

impl Display for ElfMachine {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            ElfMachine::EmNone => write!(f, "No machine"),
            ElfMachine::EmM32 => write!(f, "AT&T WE 32100"),
            ElfMachine::EmSparc => write!(f, "SPARC"),
            ElfMachine::Em386 => write!(f, "Intel 80386"),
            ElfMachine::Em68k => write!(f, "Motorola 68000"),
            ElfMachine::Em88k => write!(f, "Motorola 88000"),
            ElfMachine::Em860 => write!(f, "Intel 80860"),
            ElfMachine::EmMips => write!(f, "MIPS I Architecture"),
            ElfMachine::EmS370 => write!(f, "IBM System/370 Processor"),
            ElfMachine::EmMipsRs3Le => write!(f, "MIPS RS3000 Little-endian"),
            ElfMachine::EmParisc => write!(f, "Hewlett-Packard PA-RISC"),
            ElfMachine::EmVpp500 => write!(f, "Fujitsu VPP500"),
            ElfMachine::EmSparc32Plus => write!(f, "Enhanced instruction set SPARC"),
            ElfMachine::Em960 => write!(f, "Intel 80960"),
            ElfMachine::EmPpc => write!(f, "PowerPC"),
            ElfMachine::EmPpc64 => write!(f, "PowerPC64"),
            ElfMachine::EmS390 => write!(f, "IBM System/390 Processor"),
            ElfMachine::EmX8664 => write!(f, "AMD x86-64 architecture"),
            ElfMachine::EmAarch64 => write!(f, "ARM AARCH64"),
            ElfMachine::EmRiscv => write!(f, "RISC-V"),
            ElfMachine::EmLoProc => write!(f, "Processor-specific (low)"),
            ElfMachine::EmHiProc => write!(f, "Processor-specific (high)"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ElfVersion {
    EvNone = 0,
    EvCurrent = 1,
}

impl Display for ElfVersion {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            ElfVersion::EvNone => write!(f, "Invalid version"),
            ElfVersion::EvCurrent => write!(f, "Current version"),
        }
    }
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
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ElfParseError> {
        if bytes.len() < 64 {
            return Err(ElfParseError::InvalidSize);
        }

        let ident = EIdent::from_bytes(&bytes[0..16])?;

        let e_type = match u16::from_le_bytes([bytes[16], bytes[17]]) {
            0 => ElfType::EtNone,
            1 => ElfType::EtRel,
            2 => ElfType::EtExec,
            3 => ElfType::EtDyn,
            4 => ElfType::EtCore,
            0xff00 => ElfType::EtLoProc,
            0xffff => ElfType::EtHiProc,
            _ => return Err(ElfParseError::InvalidType),
        };

        let machine_value = u16::from_le_bytes([bytes[18], bytes[19]]);
        let machine = match machine_value {
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
            62 => ElfMachine::EmX8664, // x86-64
            183 => ElfMachine::EmAarch64,
            243 => ElfMachine::EmRiscv,
            0xff00 => ElfMachine::EmLoProc,
            0xffff => ElfMachine::EmHiProc,
            _ => {
                eprintln!("Unknown machine type: {}", machine_value);
                return Err(ElfParseError::InvalidMachine);
            }
        };

        let version = match u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]) {
            0 => ElfVersion::EvNone,
            1 => ElfVersion::EvCurrent,
            _ => return Err(ElfParseError::InvalidVersion),
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

        Ok(ElfHeader {
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
        })
    }
}

impl Display for ElfHeader {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.ident)?;
        writeln!(f, "\nELF Type: {}", self.e_type)?;
        writeln!(f, "Machine: {}", self.machine)?;
        writeln!(f, "Version: {}", self.version)?;
        writeln!(f, "Entry point address: 0x{:x}", self.entry)?;
        writeln!(f, "Start of program headers: {} (bytes into file)", self.phoff)?;
        writeln!(f, "Start of section headers: {} (bytes into file)", self.shoff)?;
        writeln!(f, "Flags: 0x{:x}", self.flags)?;
        writeln!(f, "Size of this header: {} (bytes)", self.ehsize)?;
        writeln!(f, "Size of program headers: {} (bytes)", self.phentsize)?;
        writeln!(f, "Number of program headers: {}", self.phnum)?;
        writeln!(f, "Size of section headers: {} (bytes)", self.shentsize)?;
        writeln!(f, "Number of section headers: {}", self.shnum)?;
        write!(f, "Section header string table index: {}", self.shstrndx)
    }
}
