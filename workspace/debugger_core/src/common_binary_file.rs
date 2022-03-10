use exe::PEImage;
use goblin::elf::Elf;

//TODO: docs and machO

pub enum BinaryFile {
    Elf(Vec<u8>),
    PE(PEImage),
    MachO,
}

impl BinaryFile {
    pub fn entry_point(&self) -> usize {
        match self {
            Self::Elf(e) => {
                let elf = goblin::elf::Elf::parse(&e).unwrap();
                elf.header.e_entry as usize
            },
            Self::PE(pe) => pe.pe.get_entrypoint().unwrap().0 as usize,
            _ => 0
        }
    }

    pub fn section_count(&self) -> usize {
        match self {
            Self::Elf(e) => {
                let elf = goblin::elf::Elf::parse(&e).unwrap();
                elf.section_headers.len()
            },
            Self::PE(pe) => pe.pe.get_section_table().unwrap().len(),
            _ => 0
        }
    }
}
