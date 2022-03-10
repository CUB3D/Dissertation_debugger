use std::io::Cursor;
use goblin::elf::Elf;

/// A subprogram (function) as defined by DWARF
#[derive(Clone, Debug)]
pub struct SubProgram {
    /// The name of the subprogram
    pub name: String,
    /// The address of the subprogram (relative to start)
    pub start_addr: u64,
}

#[derive(Clone, Debug)]
pub struct DebuggingInfo {
    pub subprograms: Vec<SubProgram>,
}

pub fn parse_dwarf_info(bytes: &[u8], elf_parsed: &Elf) -> DebuggingInfo {
    let mut subprograms = vec![];
    let dwarf = gimli::read::Dwarf::load(
        |id: gimli::SectionId| -> Result<std::borrow::Cow<[u8]>, gimli::Error> {
            for s in &elf_parsed.section_headers {
                if let Some(name) = elf_parsed.shdr_strtab.get_at(s.sh_name) {
                    if name == id.name() {
                        let mut data = vec![0u8; s.sh_size as usize];
                        data.copy_from_slice(bytes.get(s.file_range().unwrap()).unwrap());
                        return Ok(std::borrow::Cow::Owned(data));
                    }
                }
            }

            return Ok(std::borrow::Cow::Borrowed(&[][..]));
        },
    );

    if let Ok(dwarf) = dwarf {
        // Borrow a `Cow<[u8]>` to create an `EndianSlice`.
        let borrow_section: &dyn for<'a> Fn(
            &'a std::borrow::Cow<[u8]>,
        )
            -> gimli::EndianSlice<'a, gimli::RunTimeEndian> =
            &|section| gimli::EndianSlice::new(&*section, gimli::RunTimeEndian::Little);

        // Create `EndianSlice`s for all of the sections.
        let dwarf = dwarf.borrow(&borrow_section);

        let mut iter = dwarf.units();
        while let Some(header) = iter.next().unwrap() {
            // println!(
            //     "Unit at <.debug_info+0x{:x}>",
            //     header.offset().as_debug_info_offset().unwrap().0
            // );
            let unit = dwarf.unit(header).unwrap();

            let mut depth = 0;
            let mut entries = unit.entries();
            while let Some((delta_depth, entry)) = entries.next_dfs().unwrap() {
                depth += delta_depth;
                // println!("<{}><{:x}> {}", depth, /*entry.offset().0*/0, entry.tag());

                // Iterate over the attributes in the DIE.
                let mut attrs = entry.attrs();
                while let Some(attr) = attrs.next().unwrap() {
                    if let Ok(s) = dwarf.attr_string(&unit, attr.value()) {
                        use gimli::Reader;
                        let s = s.to_slice().expect("foobar");
                        let _s = String::from_utf8(s.to_vec());
                        // println!("   {}: {:?}", attr.name(), s);
                    } else {
                        // println!("   {}: {:?}", attr.name(), attr.value());
                    }
                }

                use fallible_iterator::*;
                let attrs = entry
                    .attrs()
                    .iterator()
                    .map(|a| a.unwrap())
                    .collect::<Vec<_>>();

                match entry.tag() {
                    gimli::DW_TAG_variable => {
                        let attrs = attrs;

                        for attr in attrs {
                            println!("Got variable {:?} - {:?}", attr.name().static_string(), attr.value().exprloc_value());
                        }
                    }

                    gimli::DW_TAG_subprogram => {
                        let name = {
                            if let Some(name) = attrs
                                .iter()
                                .find(|a| a.name() == gimli::DW_AT_name) {
                                let name_str = dwarf
                                    .attr_string(&unit, name.value())
                                    .expect("Failed to get name string");
                                use gimli::Reader;
                                let s = name_str.to_slice().expect("foobar");
                                let s = String::from_utf8(s.to_vec());
                                s.expect("String fail")
                            } else {
                                "".to_string()
                            }
                        };
                        let start_addr = {
                            let pc =
                                attrs
                                    .iter()
                                    .find(|a| a.name() == gimli::DW_AT_low_pc)
                                    .map(|pc| match pc.value() {
                                        gimli::AttributeValue::Addr(a) => a as u64,
                                        _ => unimplemented!(),
                                    });
                            pc
                        };

                        if let Some(start_addr) = start_addr {
                            subprograms.push(SubProgram { name, start_addr });
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /*if let Some(section) = elf_parsed.by_name(".rela.dyn") {
        debugger_core::elf::parse_rela(&mut Cursor::new(section.data), &elf_parsed);
    }

    if let Some(section) = elf_parsed.by_name(".rela.plt") {
        let rela = debugger_core::elf::parse_rela(&mut Cursor::new(section.data), &elf_parsed)
            .expect("failed to read rela.plt");
        for r in &rela {
            if let Some(name) = &r.name {
                subprograms.push(SubProgram {
                    name: name.clone(),
                    start_addr: r.offset,
                });
            }
        }
    }*/

    // println!("Found subroutines, {:?}", subprograms);

    // println!("symtab");
    // if let Some(section) = elf_parsed.by_name(".symtab") {
    //     crate::elf::parse_symbol_table(&mut Cursor::new(section.data), &elf_parsed);
    // }
    //
    // println!("dynstr");
    // if let Some(section) = elf_parsed.by_name(".dynsym") {
    //     crate::elf::parse_dynamic_symbol_table(&mut Cursor::new(section.data), &elf_parsed);
    // }

    DebuggingInfo { subprograms }
}

// pub fn parse_plt_relocations(elf_parsed: &Elf) -> DebuggingInfo {
//     // TODO: need to get all sections with a bit set
//     if let Some(section) = elf_parsed.by_name(".rela.plt") {
//         for e in section.
//     }
// }
