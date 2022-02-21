use crate::elf::Elf;
use exe::PEImage;

//TODO: docs and machO

pub enum BinaryFile {
    Elf(Elf),
    PE(PEImage),
    MachO,
}

impl BinaryFile {
    pub fn entry_point(&self) -> usize {
        match self {
            Self::Elf(e) => e.entry_point as usize,
            Self::PE(pe) => pe.pe.get_entrypoint().unwrap().0 as usize,
            _ => 0
        }
    }

    pub fn section_count(&self) -> usize {
        match self {
            Self::Elf(e) => e.sections.len(),
            Self::PE(pe) => pe.pe.get_section_table().unwrap().len(),
            _ => 0
        }
    }
}
