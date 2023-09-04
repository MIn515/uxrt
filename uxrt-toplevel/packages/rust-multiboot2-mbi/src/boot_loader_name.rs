
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)] // only repr(C) would add unwanted padding before first_section
pub struct BootLoaderNameTag {
    typ: u32,
    size: u32,
    string: u8,
}

impl BootLoaderNameTag {
    pub fn name(&self) -> &str {
        use core::{mem,str,slice};
        unsafe {
            let strlen = self.size as usize - mem::size_of::<BootLoaderNameTag>();
            str::from_utf8(
                slice::from_raw_parts((&self.string) as *const u8, strlen)).expect("non-UTF-8 characters found in bootloader name, in violation of the Multiboot2 specification")
        }
    }
}
