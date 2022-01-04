use crate::elf::Elf;
use exe::PEImage;

pub enum BinaryFile {
    Elf(Elf),
    PE(PEImage),
}

impl BinaryFile {
    pub fn entry_point(&self) -> usize {
        match self {
            Self::Elf(e) => e.entry_point as usize,
            Self::PE(pe) => pe.pe.get_entrypoint().unwrap().0 as usize,
        }
    }

    pub fn section_count(&self) -> usize {
        match self {
            Self::Elf(e) => e.sections.len(),
            Self::PE(pe) => pe.pe.get_section_table().unwrap().len(),
        }
    }
}
