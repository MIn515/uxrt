/* Generate an XRFS file system
 *
 * Copyright (C) 2022           Andrew Warkentin
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
*/

/*
 * Some sparse words about how to use the program
 *
 * `genxrfs' is the `mkfs' equivalent of the other filesystems, but
 * you must tell it from which directory you want to build the
 * filesystem.  I.e. all files (and directories) in that directory
 * will be part of the newly created filesystem.  Imagine it like
 * building a cd image, or creating an archive (tar, zip) file.
 *
 * Basic usage:
 * genxrfs [-p <page size>] <image> [directory]
 *
 * for example:
 * # genxrfs -o UX/RT -r 0.0 uxrt.boot build/bootimg
 *
 * If the image name is "-", the filesystem will be written to stdout.
 *
 * If no directory is specified, the current directory will be used.
 *
 * The volume name of the filesystem can be set with the -V option.  If you
 * don't specify one, genxrfs will create a volume name of the form: 'xrfs
 * xxxxxxxx', where the x's represent the current time in a cryptic
 * form.
 *
 * The page size of the filesystem can be set with the -p option. It must be a
 * power of two >= 256.
 */

#![feature(io_error_other)]

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::io::{Read, Write};
use std::fs::{self, DirEntry, File, remove_file};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::cell::Cell;
use std::mem::size_of;
use scan_fmt::scan_fmt;

extern crate intrusive_collections;
extern crate clap;

use clap::Parser;

use intrusive_collections::{
    intrusive_adapter, KeyAdapter, RBTree, RBTreeLink, LinkedList, LinkedListLink, UnsafeRef,
};

mod traits;

use crate::traits::StructAsBytes;
const XRFS_MAGIC0: u32 = 0xe85250d7;
const XRFS_MAGIC1: u32 = 0x58524653;

const MULTIBOOT_HEADER_TAG_END: u16 = 0;
const MULTIBOOT_HEADER_TAG_FS_ADDRESS: u16 = 0xa0;
const MULTIBOOT_HEADER_TAG_FS_PAGE_SIZE: u16 = 0xa1;
//const MULTIBOOT_HEADER_TAG_FS_EXPAND: u16 = 0xa2;
const MULTIBOOT_HEADER_TAG_FS_OS_NAME: u16 = 0xa3;
const MULTIBOOT_HEADER_TAG_FS_OS_VERSION: u16 = 0xa4;
const MULTIBOOT_HEADER_TAG_FS_KERNEL: u16 = 0xa5;
const MULTIBOOT_HEADER_TAG_FS_MODULE: u16 = 0xa6;
const MULTIBOOT_HEADER_TAG_FS_MODULE_EXEC: u16 = 0xa7;
const MULTIBOOT_HEADER_TAG_FS_MODULE_SPECIAL: u16 = 0xa8;
const MULTIBOOT_HEADER_TAG_FS_INFO_OFFSET: u16 = 0xa9;

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct XRFSSuperBlock {
    magic0: u32,
    magic1: u32,
    //Total header length 
    header_length: u32,
    //Total image length
    total_length: u32,
    //The above fields plus this one must equal 0 mod 2^32
    checksum: i32,
    pad: u32,
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct BaseTag {
    typ: u16,
    flags: u16,
    size: u32,
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct AddressTag {
    typ: u16,
    flags: u16,
    size: u32,
    phys_addr: u64,
    virt_addr: u64,
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct PageSizeTag {
    typ: u16,
    flags: u16,
    size: u32,
    page_size: u32,
    pad: u32,
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct InfoOffsetTag {
    typ: u16,
    flags: u16,
    size: u32,
    offset: u32,
    pad: u32,
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct ModuleTag {
    typ: u16,
    flags: u16,
    size: u32,
    mod_start: u32,
    mod_end: u32,
    padding_end: u32,
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct FileHeader {
    mode: u32,
    uid: u32,
    gid: u32,
    spec: u32,
}

///Contains all the data associated with a particular inode, as well as the path
///of its first link. Subsequent links are stored as SecondaryLink objects instead.
struct FileNode {
    source_path: PathBuf,
    header_path: String,
    dev: u64,
    inode: u64,
    size: u32,
    mem_size: Cell<u32>,
    address: Cell<u64>,
    //replacement for the autoaddress flag; this should be possible to specify in an @ filename with "auto" specified as the address
    priority: Cell<u8>,
    module_type: char,
    dereference: bool,
    address_link: RBTreeLink,
    inode_link: RBTreeLink,
    unallocated_link: LinkedListLink,
}

impl FileNode {
    fn end_address(&self, page_size: usize, header_pages: u32) -> u64 {
        ((self.address.get() + self.mem_size.get() as u64 + page_size as u64 - 1) & !(page_size as u64 - 1)) + page_size as u64 * header_pages as u64
    }
}


intrusive_adapter!(AddressAdapter = UnsafeRef<FileNode>:
    FileNode { address_link: RBTreeLink });

impl<'a> KeyAdapter<'a> for AddressAdapter {
    type Key = u64;
    fn get_key(&self, node: &'a FileNode) -> u64 {
        node.address.get()
    }
}

intrusive_adapter!(FileInodeAdapter = UnsafeRef<FileNode>:
    FileNode { inode_link: RBTreeLink });

impl<'a> KeyAdapter<'a> for FileInodeAdapter {
    type Key = u128;
    fn get_key(&self, node: &'a FileNode) -> u128 {
        get_id(node.dev, node.inode)
    }
}

intrusive_adapter!(UnallocatedAdapter = UnsafeRef<FileNode>:
    FileNode { unallocated_link: LinkedListLink });

///A link to a previously-found inode.
struct SecondaryLink {
    header_path: String,
    dev: u64,
    inode: u64,
}

#[inline(always)]
fn get_id(dev: u64, ino: u64) -> u128 {
    ((dev as u128) << size_of::<u64>()) | ino as u128
}

fn insert_unallocated(unallocated_nodes: &mut BTreeMap<u8, LinkedList<UnallocatedAdapter>>, node: UnsafeRef<FileNode>){
    let priority = node.priority.get();
    if unallocated_nodes.get(&priority).is_none(){
        unallocated_nodes.insert(priority, Default::default());
    }

    unallocated_nodes.get_mut(&priority).unwrap().push_front(node);
}

struct Filesystem {
    opts: Opts,
    base_path: PathBuf,
    allocated_nodes: RBTree<AddressAdapter>,
    all_nodes: RBTree<FileInodeAdapter>,
    unallocated_nodes: BTreeMap<u8, LinkedList<UnallocatedAdapter>>,
    secondary_links: VecDeque<SecondaryLink>,
    start_address: u64,
    end_address: u64,
}

impl Filesystem {
    fn new(opts: Opts, base_path: &Path) -> Filesystem{
        Filesystem {
            opts,
            base_path: base_path.to_path_buf(),
            allocated_nodes: Default::default(),
            all_nodes: Default::default(),
            unallocated_nodes: Default::default(),
            secondary_links: Default::default(),
            start_address: 0,
            end_address: 0,
        }
    }
    fn header_pages(&self) -> u32 {
        if self.opts.no_unix_metadata {
            1
        }else{
            2
        }
    }
    fn process_dir(&mut self, dir: &Path) -> io::Result<()> {
        if dir.is_dir() {
            let header_prefix = dir.strip_prefix(&self.base_path).expect("process_dir() called on directory that is not child of base_path (shouldn't happen!)");
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    self.process_dir(&path)?;
                }
                self.process_entry(&entry, &header_prefix)?;
            }
        }
        Ok(())
    }
    fn process_entry(&mut self, entry: &DirEntry, dir_prefix: &Path) -> io::Result<()>{
        let path = entry.path();
        let metadata_opt = entry.metadata();
        if let Err(err) = metadata_opt{
            eprintln!("lstat failed for {}: {}", path.to_string_lossy(), err);
            exit(1);
        }
        let mut metadata = metadata_opt.unwrap();
        let name_opt = path.file_name();
        if name_opt.is_none(){
            return Ok(());
        }
        let mut dereference = false; 
        let mut address = None;
        let mut mem_size_str = None;
        let mut priority = u8::MAX;
        let mut module_type = 'm';
        let mut name = name_opt.unwrap().to_string_lossy().to_string();
        let mut special_name = false;
        //Handle special names (any symlink that is matched here will be
        //dereferenced while building the image, unlike all other symlinks,
        //which will be included as is)
        if name.as_bytes()[0] == '@' as u8 {
            special_name = true;
            //file to be placed automatically with a user-specified priority
            //and in-memory size
            if let Ok(res) = scan_fmt!(&name, "@{[^,]},auto,{d},{[^,]},{/[a-z]/}{e}", String, u8, String, char){
                dereference = true;
                let (name_field, priority_field, mem_size_field, module_type_field) = res;
                name = name_field;
                priority = priority_field;
                mem_size_str = Some(mem_size_field);
                module_type = module_type_field;
            //file with a user-specified address and in-memory size
            }else if let Ok(res) = scan_fmt!(&name, "@{[^,]},0x{x},{[^,]},{/[a-z]/}{e}", String, [hex u64], String, char){
                dereference = true;
                let (name_field, address_field, mem_size_field, module_type_field) = res;
                name = name_field;
                address = Some(address_field);
                mem_size_str = Some(mem_size_field);
                module_type = module_type_field;
            //any other
            }else if let Ok(res) = scan_fmt!(&name, "@{}", String){
                dereference = true;
                name = res;
            }
        }
        if dereference {
            let metadata_opt = path.metadata();
            if let Err(err) = metadata_opt{
                eprintln!("stat failed for {}: {}", path.to_string_lossy(), err);
                exit(1);
            }
            metadata = metadata_opt.unwrap();
        }

        //ignore everything other than regular files if Unix metadata isn't
        //being included
        if !metadata.is_file() && self.opts.no_unix_metadata {
            return Ok(());
        }

        let size = if metadata.is_file(){
            metadata.size()
        }else if metadata.is_symlink(){
            self.opts.page_size as u64
        }else{
            0
        };
        let aligned_size = (size + self.opts.page_size as u64 - 1) & !(self.opts.page_size as u64);
        let mut mem_size = if let Some(s) = mem_size_str {
            if s == "auto"{
                size
            }else if let Ok(i) = s.parse::<u64>(){
                i 
            }else{
                0
            }
        }else if metadata.is_symlink(){
            self.opts.page_size as u64
        }else if !metadata.is_file(){
            0
        }else{
            size
        };
        mem_size = (mem_size + self.opts.page_size as u64 - 1) & !((self.opts.page_size - 1) as u64);

        if !metadata.is_file() && special_name {
            eprintln!("path with special name {} is not a regular file", path.to_string_lossy());
            exit(1);
        }


        let header_path = {
            let mut buf = PathBuf::from("/");
            buf.push(dir_prefix);
            buf.push(name);
            buf.to_string_lossy().to_string()
        };

        if mem_size > u32::MAX as u64 {
            eprintln!("in-memory size of {} too big for XRFS image (size: {} max: {})", path.to_string_lossy(), size, u32::MAX);
            exit(1);
        }
        let mut address_modified = false;
        let mut priority_modified = false;
        let file_id = get_id(metadata.dev(), metadata.ino());
        let mut cursor = self.all_nodes.find_mut(&file_id);
        let node_opt = cursor.get();
        if let Some(existing_node) = node_opt {
            let existing_address = existing_node.address.get();
            if address.is_some() {
                if existing_address != 0 && Some(existing_address) != address {
                    eprintln!("conflicting addresses {:x} and {:x} for file {}", existing_address, address.unwrap(), path.to_string_lossy());
                    exit(1);
                }else{
                    existing_node.address.set(address.unwrap());
                    address_modified = true;
                }
            }
            let existing_mem_size = existing_node.mem_size.get();
            if existing_mem_size != existing_node.size && mem_size != aligned_size && mem_size != existing_mem_size as u64 {
                eprintln!("conflicting in-memory sizes {} and {} for file {}", mem_size, existing_mem_size, path.to_string_lossy());
                exit(1);
            }
            existing_node.mem_size.set(mem_size as u32);
            if priority > existing_node.priority.get(){
                existing_node.priority.set(priority);
                priority_modified = true;
            }
            self.secondary_links.push_front(SecondaryLink {
                header_path,
                dev: metadata.dev(),
                inode: metadata.ino(),
            });
        }else{
            if size > u32::MAX as u64 {
                eprintln!("size of {} too big for XRFS image (size: {} max: {})", path.to_string_lossy(), size, u32::MAX);
                exit(1);
            }
            let node = UnsafeRef::from_box(Box::new(FileNode {
                source_path: path,
                header_path,
                dev: metadata.dev(),
                inode: metadata.ino(),
                size: size as u32,
                mem_size: Cell::new(mem_size as u32),
                address: Cell::new(0),
                priority: Cell::new(priority),
                module_type,
                dereference,
                address_link: Default::default(),
                inode_link: Default::default(),
                unallocated_link: Default::default(),
            }));
            if let Some(a) = address {
                node.address.set(a);
                self.allocated_nodes.insert(node.clone());
            }else{
                insert_unallocated(&mut self.unallocated_nodes, node.clone());
            }
            cursor.insert(node);
        }
        if address_modified {
            let node_ref = cursor.remove().unwrap();
            self.allocated_nodes.insert(node_ref.clone());
            cursor.insert(node_ref);
        }
        if priority_modified {
            let node_ref = cursor.remove().unwrap();
            insert_unallocated(&mut self.unallocated_nodes, node_ref.clone());
            cursor.insert(node_ref);
        }

        Ok(())
    }
    fn allocate_addresses(&mut self){
        //the superblock and the string-less initial tags (page size, info
        //offset, and address if required) are all placed into the first page;
        //all subsequent tags are page-aligned to simplify allocation, and the
        //two extra pages are for the module tag and Unix metadata for the
        //first file
        let mut initial_pages = 1;

        if self.opts.os_name.is_some(){
            //OS name tag
            initial_pages += 1;
        }

        if self.opts.os_ver.is_some(){
            //OS version tag
            initial_pages += 1;
        }

        let mut cur_addr = if let Some(node) = self.allocated_nodes.back().get(){
            node.end_address(self.opts.page_size, self.header_pages())
        }else{
            ((initial_pages + self.header_pages()) * self.opts.page_size as u32) as u64
        };


        let header_pages = self.header_pages();
        for (priority, tree) in self.unallocated_nodes.iter_mut() {
            while let Some(node) = tree.pop_back(){
                //the first condition means the first link for this file
                //didn't specify an address so it got placed on the 
                //unallocated list, but a later one did
                //
                //the second one means that the first link specified a lower 
                //priority than a later one
                //
                //either way, it already ended up on the allocated list
                //
                //0 is an illegal starting address for a file since the start 
                //of the data must at least allow for the superblock and
                //initial tags
                if node.address.get() != 0 || node.priority.get() != *priority{
                    continue
                }
                node.address.set(cur_addr);
                cur_addr = node.end_address(self.opts.page_size, header_pages);
                self.allocated_nodes.insert(node);
            }
        }

        let mut cursor = self.allocated_nodes.front();

        if cursor.is_null(){
            eprintln!("source directory {} is empty", self.opts.directory);
            exit(1);
        }

        self.start_address = cursor.get().unwrap().address.get() - ((initial_pages + self.header_pages()) * self.opts.page_size as u32) as u64;

        let last_node = self.allocated_nodes.back().get().unwrap();
        self.end_address = last_node.address.get() 
            + last_node.mem_size.get() as u64 
            + self.opts.page_size as u64 * (self.secondary_links.len() + 1) as u64;

        while let Some(node) = cursor.get(){
            if node.address.get() < (initial_pages * self.opts.page_size as u32) as u64 {
                eprintln!("starting address of first file {} below start of initial Multiboot tags", node.source_path.to_string_lossy());
                exit(1);
            }


            if let Some(next_node) = cursor.peek_next().get(){
                if node.address.get() % self.opts.page_size as u64 != 0 {
                    eprintln!("address of file {} ({:x}) not page-aligned", node.source_path.to_string_lossy(), node.address.get());
                    exit(1);
                }
                if node.address.get() + node.mem_size.get() as u64 + (self.opts.page_size * self.header_pages() as usize) as u64 > next_node.address.get() {
                    eprintln!("end address of file {} ({:x}) overlaps start address of file {} ({:x})", node.source_path.to_string_lossy(), node.address.get(), next_node.source_path.to_string_lossy(), next_node.address.get());
                    exit(1);
                }
            }
            cursor.move_next();
        }
    }
    fn generate_module_tag(&self, node: &FileNode, secondary_link: Option<&SecondaryLink>) -> Result<Vec<u8>, io::Error>{
        let mut typ = match node.module_type {
            'k' => MULTIBOOT_HEADER_TAG_FS_KERNEL,
            'x' => MULTIBOOT_HEADER_TAG_FS_MODULE_EXEC,
            'm' => MULTIBOOT_HEADER_TAG_FS_MODULE,
            _ => 0,
        };
        if !node.source_path.is_file(){
            typ = MULTIBOOT_HEADER_TAG_FS_MODULE_SPECIAL;
        }else if typ == 0 {
            eprintln!("invalid tag type for {}", node.source_path.to_string_lossy());
            return Err(io::Error::other("invalid tag type"));
        }

        let mod_start = (node.address.get() - self.start_address) as u32;
        let size = if secondary_link.is_some() {
            self.opts.page_size as u32
        }else{
            (self.opts.page_size as u32 * self.header_pages()) + node.mem_size.get() as u32
        };

        let tag = ModuleTag {
            typ,
            flags: 0,
            size,
            mod_start,
            mod_end: mod_start + node.size as u32,
            padding_end: mod_start + node.mem_size.get(),
        };
        let header_path = if let Some(link) = secondary_link {
            &link.header_path
        }else{
            &node.header_path
        };
        if let Ok(raw_tag) = tag.struct_as_bytes_aligned_with_string(self.opts.page_size, header_path) {
            Ok(raw_tag)
        }else{
            eprintln!("path of {} too long", node.source_path.to_string_lossy());
            return Err(io::Error::other("path too long"));
        }
    }

    fn write_image(&mut self, image: &mut File) -> io::Result<()>{
        let magic1 = XRFS_MAGIC1.to_be();
        let total_length = (self.end_address - self.start_address) as u32;
        let checksum = -((XRFS_MAGIC0
                         .overflowing_add(magic1).0
                         .overflowing_add(total_length).0
                         .overflowing_add(total_length).0) as i32);
        //the header spans the entire length of the image (the file data is 
        //stored within the first tag associated with that inode), so 
        //header_length and total_length are the same
        let header = XRFSSuperBlock {
            magic0: XRFS_MAGIC0,
            magic1,
            header_length: total_length,
            total_length,
            checksum,
            pad: 0,
        };
        if self.opts.verbose {
            println!("image length: {}", total_length);
        }
        if self.opts.verbose {
            println!("page size: {}", self.opts.page_size);
        }
        let mut initial_page = header.struct_as_bytes();

        if self.start_address != 0 {
            let address_tag = AddressTag {
                typ: MULTIBOOT_HEADER_TAG_FS_ADDRESS,
                flags: 0,
                size: size_of::<AddressTag>() as u32,
                phys_addr: self.start_address,
                virt_addr: self.start_address,
            };
            initial_page.append(&mut address_tag.struct_as_bytes());
            if self.opts.verbose {
                println!("start address: {:x}", self.start_address);
            }
        }

        if !self.opts.no_unix_metadata {
            let info_offset_tag = InfoOffsetTag {
                typ: MULTIBOOT_HEADER_TAG_FS_INFO_OFFSET,
                flags: 0,
                size: size_of::<InfoOffsetTag>() as u32,
                offset: self.opts.page_size as u32,
                pad: 0,
            };

            initial_page.append(&mut info_offset_tag.struct_as_bytes());
        }

        //since this is the last tag in the initial page, the size includes
        //the padding to fill out the remainder of the page
        let page_size_tag_size = (self.opts.page_size - initial_page.len()) as u32;
        let page_size_tag = PageSizeTag {
            typ: MULTIBOOT_HEADER_TAG_FS_PAGE_SIZE,
            flags: 0,
            size: page_size_tag_size,
            page_size: self.opts.page_size as u32,
            pad: 0,
        };
        initial_page.append(&mut page_size_tag.struct_as_bytes());

        initial_page.resize(self.opts.page_size, 0);

        image.write(&initial_page)?;

        if self.opts.os_name.is_some(){
            let os_name_tag = BaseTag {
                typ: MULTIBOOT_HEADER_TAG_FS_OS_NAME,
                flags: 0,
                size: self.opts.page_size as u32,
            };
            if let Ok(tag) = os_name_tag.struct_as_bytes_aligned_with_string(self.opts.page_size, self.opts.os_name.as_ref().unwrap()){
                image.write(&tag)?;
            }else{
                return Err(io::Error::other("OS name too long"));
            }
            if self.opts.verbose {
                println!("OS name: {}", self.opts.os_name.as_ref().unwrap());
            }
        }

        if self.opts.os_ver.is_some(){
            let os_version_tag = BaseTag {
                typ: MULTIBOOT_HEADER_TAG_FS_OS_VERSION,
                flags: 0,
                size: self.opts.page_size as u32,
            };
            if let Ok(tag) = os_version_tag.struct_as_bytes_aligned_with_string(self.opts.page_size, self.opts.os_ver.as_ref().unwrap()){
                image.write(&tag)?;
            }else{
                return Err(io::Error::other("OS version too long"));
            }
            if self.opts.verbose {
                println!("OS version: {}", self.opts.os_ver.as_ref().unwrap());
            }
        }
        if self.opts.verbose {
            println!("--- primary modules ---");
        }
        let mut cursor = self.allocated_nodes.front();
        while let Some(node) = cursor.get(){
            cursor.move_next();
            let tag = self.generate_module_tag(node, None)?; 
            image.write(&tag)?;
            let res = if node.dereference {
                node.source_path.metadata()
            }else{
                node.source_path.symlink_metadata()
            };
            let metadata_opt = res;
            if let Err(err) = metadata_opt{
                return Err(err);
            }
            let metadata = metadata_opt.unwrap();
            let header = FileHeader {
                mode: metadata.mode(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                spec: 0,
            };
            if self.opts.verbose {
                println!("{}", node.header_path);
                if node.size == 0 {
                    println!("    [{:x}, {:x}] {} {} {:o}, sz {}, memsz {}, at 0x{:x}", node.dev, node.inode, metadata.uid(), metadata.gid(), metadata.mode(), node.size, node.mem_size.get(), node.address.get());
                }else{
                    println!("    [{:x}, {:x}] {} {} {:o}, sz {}, memsz {}, at 0x{:x}", node.dev, node.inode, metadata.uid(), metadata.gid(), metadata.mode(), node.size, node.mem_size.get(), node.address.get());
                }
            }
            if !self.opts.no_unix_metadata {
                image.write(&header.struct_as_bytes_aligned(self.opts.page_size))?;
            }
            let mut buf = Vec::new();
            buf.resize(self.opts.page_size, 0 as u8);

            if metadata.is_file(){
                let mut f = match File::open(&node.source_path) {
                    Ok(res) => res,
                    Err(err) => {
                        eprintln!("cannot open {}: {}", node.source_path.to_string_lossy(), err);
                        return Err(err);
                    },
                };
                let mut total_bytes = 0;
                let mut bytes = 1;
                while bytes > 0 {
                    bytes = match f.read(&mut buf[0..self.opts.page_size]) {
                        Ok(b) => b,
                        Err(err) => {
                            eprintln!("cannot read {}: {}", node.source_path.to_string_lossy(), err);
                            return Err(err);
                        }
                    };
                    if let Err(err) = image.write(&buf[0..bytes]){
                        return Err(err);
                    }
                    total_bytes += bytes;
                }
                if total_bytes != node.size as usize {
                    eprintln!("size of {} changed during image generation", node.source_path.to_string_lossy());
                    return Err(io::Error::other("file size changed"));
                }
                bytes = (node.mem_size.get() - node.size) as usize;
                buf[0..self.opts.page_size].fill(0);
                while bytes > 0 {
                    let end = if bytes > self.opts.page_size {
                        self.opts.page_size
                    }else{
                        bytes
                    };
                    image.write(&buf[0..end])?;
                    bytes -= end;
                }
            }else if metadata.is_symlink(){
                let target_path = match node.source_path.read_link() {
                    Ok(t) => t,
                    Err(err) => {
                        eprintln!("cannot read link {}: {}", node.source_path.to_string_lossy(), err);
                        return Err(err);
                    },
                };
                let target_string = target_path.to_string_lossy();
                if self.opts.verbose {
                    println!("    symlink to {}", target_string);
                }
                let target_bytes = target_string.as_bytes();
                let link_max = self.opts.page_size - 1;
                if target_bytes.len() > link_max {
                    eprintln!("target path {} of symlink {} is longer than the maximum of {}", target_string, node.source_path.to_string_lossy(), link_max); 
                    return Err(io::Error::other("OS version too long"));
                }
                buf[0..target_bytes.len()].copy_from_slice(target_bytes);
                buf[target_bytes.len()..self.opts.page_size].fill(0);
                image.write(&buf)?;
            }
        }
        if self.opts.verbose && self.secondary_links.len() != 0 {
            println!("--- secondary modules ---");
        }
        while let Some(link) = self.secondary_links.pop_back(){
            let file_id = get_id(link.dev, link.inode);
            let node = self.all_nodes.find(&file_id).get().expect("secondary link without original node");
            let tag = self.generate_module_tag(node, Some(&link))?;
            if self.opts.verbose {
                println!("{}", link.header_path);
                println!("    hard link to {}", node.header_path);
            }

            image.write(&tag)?;
        }
        let end_tag = BaseTag {
            typ: MULTIBOOT_HEADER_TAG_END,
            flags: 0,
            size: self.opts.page_size as u32,
        };
        image.write(&end_tag.struct_as_bytes_aligned(self.opts.page_size))?;
 
        Ok(())
    }
}

fn valid_page_size(s: &str) -> Result<usize, String> {
    let page_size: usize = s
        .parse()
        .map_err(|_| format!("invalid page size {}", s))?;
    if page_size >= u32::MAX as usize {
        Err(format!("page size {} exceeds the maximum of {}", page_size, u32::MAX))
    }else if page_size & (page_size - 1) == 0 && page_size >= 256{
        Ok(page_size)
    }else{
        Err(format!("page size {} is not a power of 2 >= 256.", page_size))
    }
}

///Create an xrfs filesystem image from a directory
#[derive(Parser)]
struct Opts {
    ///(Too) verbose operation
    #[clap(short, long)]
    verbose: bool,

    ///Don't include Unix metadata headers
    #[clap(short, long)]
    no_unix_metadata: bool,

    ///Specify the Multiboot OS name string
    #[clap(short, long)]
    os_name: Option<String>,

    ///Specify the Multiboot OS version string
    #[clap(short('r'), long)]
    os_ver: Option<String>,

    ///Use the specified page size (must be a power of 2 greater than or equal to 256)
    #[clap(short, long, default_value_t = 4096, value_parser = valid_page_size)]
    page_size: usize,

    /////Exclude all objects matching pattern
    //#[clap(short('x'), long)]
    //exclude: Option<String>,

    image: String,

    #[clap(default_value = ".")]
    directory: String,
}

fn main() {
    let opts = Opts::parse();

    let orig_dir = opts.directory.clone();

    let dir_path = Path::new(orig_dir.as_str());
    if let Err(err) = dir_path.try_exists() {
        eprintln!("error: cannot access source path {}: {}", dir_path.display(), err);
        exit(1);
    }
    if !dir_path.is_dir() {
        eprintln!("error: source path {} is not a directory", dir_path.display());
        exit(1);
    }
    let mut filesystem = Filesystem::new(opts, dir_path);
    if let Err(err) = filesystem.process_dir(dir_path){
        eprintln!("{}", err);
        exit(1);
    }
    filesystem.allocate_addresses();
    let orig_img = filesystem.opts.image.clone();
    let img_path = Path::new(orig_img.as_str());
    let img_fd = File::create(img_path);
    match img_fd {
        Ok(mut f) => {
            if let Err(err) = filesystem.write_image(&mut f){
                let _ = remove_file(img_path);
                eprintln!("generating image {} failed: {}", filesystem.opts.image, err);
                exit(1);
            }
        },
        Err(err) => {
            eprintln!("cannot open image {}: {}", filesystem.opts.image, err);
            exit(1);
        }

    }
}
