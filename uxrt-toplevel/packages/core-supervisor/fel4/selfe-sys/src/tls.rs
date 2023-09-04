use crate::{
    seL4_BootInfo, seL4_IPCBuffer
};
#[cfg(feature = "tls")]
extern "C" {
    #[link_name = "selfe_tls_init_root"]
    pub fn init_root(bootinfo: *mut seL4_BootInfo);
    #[link_name = "selfe_get_tls_size"]
    pub fn get_size() -> usize;
    #[link_name = "selfe_write_tls_image"]
    pub fn write_image(tls_memory: *mut u8) -> usize;
    #[link_name = "selfe_write_tls_image_with_ipcbuf"]
    pub fn write_image_with_ipcbuf(tls_memory: *mut u8, ipcbuf: *const seL4_IPCBuffer) -> usize;
    #[link_name = "selfe_write_tls_variable"]
    pub fn write_variable(dest_tls_base: *mut u8) -> usize;
}

#[cfg(not(feature = "tls"))]
pub fn init_root(bootinfo: *mut seL4_BootInfo){
}
