pub unsafe extern "C" fn selfe_tls_init_root(bootinfo: *mut seL4_BootInfo){
    unimplemented!();
}
pub unsafe extern "C" fn selfe_get_tls_size() -> usize {
    unimplemented!();
}
pub unsafe extern "C" fn selfe_write_tls_image(tls_memory: *mut u8) -> usize{
    unimplemented!();
}

pub unsafe extern "C" fn selfe_write_tls_image_with_ipcbuf(tls_memory: *mut u8, ipcbuf: *const seL4_IPCBuffer) -> usize{
    unimplemented!();
}
pub unsafe extern "C" fn selfe_write_tls_variable(dest_tls_base: *mut u8) -> usize{
    unimplemented!();
}
