use std::error::Error;
use std::io;
use std::io::{Cursor, Read, Seek, SeekFrom};

#[derive(Debug, Clone)]
pub struct Elf {
    pub entry_point: u64,
    pub sections: Vec<Section>,
    pub data: Vec<u8>,
}
//TODO: should refactor to parse head/sections seperate and store data, so we can get strings
//TODO: maybe could make this zero copy?

impl Elf {
    pub fn from_sections(entry_point: u64, sections: Vec<Section>, data: Vec<u8>) -> Self {
        Elf {
            entry_point,
            sections,
            data,
        }
    }

    pub fn by_name(&self, target: &str) -> Option<Section> {
        self.sections.iter().find(|s| s.name == target).cloned()
    }
}

#[derive(Debug, Clone)]
pub struct Section {
    _type: u32,
    pub data: Vec<u8>,
    name_offset: u32,
    pub name: String,
    pub addr: u64,
}

pub fn parse<T: Read + Seek>(from: &mut T) -> Result<Elf, Box<dyn Error>> {
    let _magic = from.read_u32()?;
    let _bit = from.read_u8()?;
    let _endian = from.read_u8()?;
    let _version = from.read_u8()?;
    let _abi = from.read_u8()?;
    let _abi_version = from.read_u8()?;
    let mut padding = [0u8; 7];
    from.read_exact(&mut padding)?;
    let _flags = from.read_u16()?;
    let _isa = from.read_u16()?;
    let _elf_version = from.read_u32()?;
    let _entry_pos = from.read_u64()?;
    let _prog_header_pos = from.read_u64()?;
    let _section_header_pos = from.read_u64()?;
    let _arch_flags = from.read_u32()?;
    let _head_size = from.read_u16()?;
    let _prog_header_entry_size = from.read_u16()?;
    let _prog_header_entry_count = from.read_u16()?;
    let _second_header_entry_size = from.read_u16()?;
    let _second_header_entry_count = from.read_u16()?;
    let section_names_index = from.read_u16()?;

    debug_assert!(_bit == 2, "64 bit only in 2021 please");
    // debug_assert_eq!(_isa, 0xF3, "RISCv only please");

    from.seek(SeekFrom::Start(_section_header_pos))?;
    let mut sections = Vec::with_capacity(_second_header_entry_count as usize);

    for _ in 0.._second_header_entry_count {
        let _name = from.read_u32()?;
        let _type = from.read_u32()?;
        let _flags = from.read_u64()?;
        let addr = from.read_u64()?;
        let offset = from.read_u64()?;
        let size = from.read_u64()?;
        let _link = from.read_u32()?;
        let _info = from.read_u32()?;
        let _addralign = from.read_u64()?;
        let _entsize = from.read_u64()?;

        // Get the data for the section
        let pos = from.stream_position().unwrap();
        from.seek(SeekFrom::Start(offset)).unwrap();
        let mut data = vec![0u8; size as usize];
        println!("Fix this here in elf");
        // from.read_exact(&mut data)?;
        from.read(&mut data)?;
        println!("T");

        // Go back to this section
        from.seek(SeekFrom::Start(pos)).unwrap();

        sections.push(Section {
            name_offset: _name as u32,
            _type,
            data,
            name: String::new(),
            addr,
        })
    }

    println!("SN");

    let section_name_section = sections.get(section_names_index as usize).cloned().unwrap();

    for s in sections.iter_mut() {
        let name = &section_name_section.data[s.name_offset as usize..];
        let strlen = name.iter().position(|p| *p == 0u8).unwrap();
        let name = &name[..strlen];
        let name = String::from_utf8_lossy(name);
        s.name = name.to_string();
    }

    // Copy all data
    from.seek(SeekFrom::Start(0)).unwrap();
    let mut data = vec![0u8; from.stream_len()? as usize];
    from.read_exact(&mut data)?;

    Ok(Elf::from_sections(
        _entry_pos,
        sections,
        data,
    ))
}

#[derive(Clone, Debug)]
pub struct Rela {
    pub offset: u64,
    pub sym: u32,
    pub type_: u32,
    pub r_addend: u64,
    pub name: Option<String>,
}

pub fn parse_rela<T: Read + Seek>(from: &mut T, elf: &Elf) -> Result<Vec<Rela>, Box<dyn Error>> {
    let section = elf.by_name(".dynsym").expect("No dynstr");
    let dynstr = parse_dynamic_symbol_table(&mut Cursor::new(&section.data), elf)?;

    let mut parse_rela = || -> Result<Rela, Box<dyn Error>> {
        let addr = from.read_u64()?;
        let info = from.read_u64()?;
        let r_addend = from.read_u64()?;

        let sym = info >> 32;
        let type_ = info & 0xffff_ffff;

        //TODO: do we just copy entire symbol, not just name?
        //TODO: we really need a way to do this by reference
        let name = dynstr.get(sym as usize).map(|name| name.name.clone());

        Ok(Rela {
            offset: addr,
            sym: sym as u32,
            type_: type_ as u32,
            name,
            r_addend
        })
    };

    let mut relocations = Vec::new();

    while let Ok(rela) = parse_rela() {
        // println!("Rela: {:?}", rela);
        relocations.push(rela);
    }

    Ok(relocations)
}

pub fn parse_symbol_table<T: Read + Seek>(from: &mut T, elf: &Elf) -> Result<Vec<()>, Box<dyn Error>> {
    for _ in 0..64 {
        let name = from.read_u32()?;
        let info = from.read_u8()?;
        let _reserved = from.read_u8()?;
        let shndx = from.read_u16()?;
        let addr = from.read_u64()?;
        let size = from.read_u64()?;

        let bind = info >> 4;
        let type_ = info & 0xf;

        // let x: Vec<_> = elf.sections.iter().map(|s| s.name.clone()).collect();
        // println!("{:?}", x);

        let dynstr = elf.by_name(".strtab").expect("No dynstr");
        let name = &dynstr.data[name as usize..];
        let strlen = name.iter().position(|p| *p == 0u8).unwrap();
        let name = &name[..strlen];
        let name = String::from_utf8_lossy(name);

        println!("Bind: {:2x} Type: {:2x} shndx:{:4x} Addr: {:4x} Size: {:4x} Name: {}", bind, type_, shndx, addr, size, name);
    }

    Ok(vec![])
}

#[derive(Clone, Debug)]
pub struct DynamicSymbol {
    name: String,
    bind: u8,
    type_: u8,
    shndx: u16,
    addr: u64,
    size: u64,
}

pub fn parse_dynamic_symbol_table<T: Read + Seek>(from: &mut T, elf: &Elf) -> Result<Vec<DynamicSymbol>, Box<dyn Error>> {
    let mut symbols = Vec::new();
    let dynstr = elf.by_name(".dynstr").expect("No dynstr");

    let mut read_dynamic_symbol = || -> Result<DynamicSymbol, Box<dyn Error>> {
        let name = from.read_u32()?;
        let info = from.read_u8()?;
        let _reserved = from.read_u8()?;
        let shndx = from.read_u16()?;
        let addr = from.read_u64()?;
        let size = from.read_u64()?;

        let bind = info >> 4;
        let type_ = info & 0xf;

        let name = &dynstr.data[name as usize..];
        let strlen = name.iter().position(|p| *p == 0u8).unwrap();
        let name = &name[..strlen];
        let name = String::from_utf8_lossy(name);

        Ok(DynamicSymbol {
            name: name.to_string(),
            bind,
            type_,
            shndx,
            addr,
            size
        })
    };

    while let Ok(dynsym) = read_dynamic_symbol() {
        symbols.push(dynsym);
    }

    Ok(symbols)
}


trait SimpleRead {
    fn read_u8(&mut self) -> io::Result<u8>;
    fn read_u16(&mut self) -> io::Result<u16>;
    fn read_u32(&mut self) -> io::Result<u32>;
    fn read_s32(&mut self) -> io::Result<i32>;
    fn read_u64(&mut self) -> io::Result<u64>;
}

impl<T: Read> SimpleRead for T {
    fn read_u8(&mut self) -> io::Result<u8> {
        let mut buf: [u8; 1] = [0; 1];
        self.read_exact(&mut buf).map(|_| u8::from_le_bytes(buf))
    }
    fn read_u16(&mut self) -> io::Result<u16> {
        let mut buf: [u8; 2] = [0; 2];
        self.read_exact(&mut buf).map(|_| u16::from_le_bytes(buf))
    }
    fn read_u32(&mut self) -> io::Result<u32> {
        let mut buf: [u8; 4] = [0; 4];
        self.read_exact(&mut buf).map(|_| u32::from_le_bytes(buf))
    }
    fn read_s32(&mut self) -> io::Result<i32> {
        let mut buf: [u8; 4] = [0; 4];
        self.read_exact(&mut buf).map(|_| i32::from_le_bytes(buf))
    }
    fn read_u64(&mut self) -> io::Result<u64> {
        let mut buf: [u8; 8] = [0; 8];
        self.read_exact(&mut buf).map(|_| u64::from_le_bytes(buf))
    }
}
