use core::mem;
use header::{Tag, TagIter};
use TAG_MODULE;
use TAG_XHI_MODULE_IMAGE;
use TAG_XHI_MODULE_EXEC;

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct ModuleTag {
    typ: u32,
    size: u32,
    mod_start: u32,
    mod_end: u32,
    name_byte: u8,
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct ExecModuleTag {
    typ: u32,
    size: u32,
    mod_start: u32,
    mod_end: u32,
    padding_end: u32,
    sections: u32,
    name_byte: u8,
}



pub trait BaseModuleTag {
    fn start_address(&self) -> u32;
    fn end_address(&self) -> u32;
    fn size(&self) -> u32;
    fn name_byte(&self) -> *const u8;
    fn base_size(&self) -> usize;
    fn name(&self) -> &str {
        use core::{str,slice};
        let strlen = self.size() as usize - self.base_size();
        unsafe {
            str::from_utf8(
                slice::from_raw_parts(self.name_byte(), strlen)).expect("non-UTF-8 characters found in module command line, in violation of the Multiboot2 specification")
        }
    }
}

impl ModuleTag {
}

impl BaseModuleTag for ModuleTag {
    fn start_address(&self) -> u32 {
        self.mod_start
    }
    fn end_address(&self) -> u32 {
        self.mod_end
    }
    fn size(&self) -> u32 {
        self.size
    }
    fn name_byte(&self) -> *const u8 {
        &self.name_byte as *const u8
    }
    fn base_size(&self) -> usize {
        mem::size_of::<ModuleTag>()
    }
}

impl ExecModuleTag {
    pub fn padding_end(&self) -> u32 {
        self.padding_end
    }
    pub fn sections(&self) -> u32 {
        self.sections
    }
}

impl BaseModuleTag for ExecModuleTag {
    fn start_address(&self) -> u32 {
        self.mod_start
    }
    fn end_address(&self) -> u32 {
        self.mod_end
    }
    fn size(&self) -> u32 {
        self.size
    }
    fn name_byte(&self) -> *const u8 {
        &self.name_byte as *const u8
    }
    fn base_size(&self) -> usize {
        mem::size_of::<ExecModuleTag>()
    }
}

pub fn module_iter_raw(iter: TagIter, typ: u32) -> ModuleIter {
    ModuleIter { iter, typ }
}

pub fn module_iter(iter: TagIter) -> ModuleIter {
    module_iter_raw(iter, TAG_MODULE)
}

pub fn module_iter_fs_image(iter: TagIter) -> ModuleIter {
    module_iter_raw(iter, TAG_XHI_MODULE_IMAGE)
}

#[derive(Clone, Debug)]
pub struct ModuleIter {
    iter: TagIter,
    typ: u32,
}

impl Iterator for ModuleIter {
    type Item = &'static dyn BaseModuleTag;

    fn next(&mut self) -> Option<&'static dyn BaseModuleTag> {
        let typ = self.typ;
        self.iter.find(|x| x.typ == typ)
            .map(|tag| unsafe{&*(tag as *const Tag as *const ModuleTag as *const dyn BaseModuleTag)})
    }
}

pub fn module_iter_exec(iter: TagIter) -> ExecModuleIter {
    ExecModuleIter { iter }
}

#[derive(Clone, Debug)]
pub struct ExecModuleIter {
    iter: TagIter,
}

impl Iterator for ExecModuleIter {
    type Item = &'static ExecModuleTag;

    fn next(&mut self) -> Option<&'static ExecModuleTag> {
        self.iter.find(|x| x.typ == TAG_XHI_MODULE_EXEC)
            .map(|tag| unsafe{&*(tag as *const Tag as *const ExecModuleTag)})
    }
}
