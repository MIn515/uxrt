pub const seL4_WordBits: usize = core::mem::size_of::<usize>() * 8;

#[allow(dead_code)]
#[cfg(any(target_arch = "x86", target_arch = "arm"))]
pub mod c_types {
    pub type c_uint = u32;
    pub type c_int = i32;

    pub type c_ulong = u32;
    pub type c_long = u32;

    pub type c_uchar = u8;
    pub type c_char = i8;
    pub type c_schar = i8;

    pub type c_ushort = u16;
    pub type c_short = i16;

    pub type c_ulonglong = u64;
    pub type c_longlong = i64;
}

#[cfg(any(target_arch = "x86", target_arch = "arm"))]
pub type seL4_RawWord = u32;

#[allow(dead_code)]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub mod c_types {
    pub type c_uint = u32;
    pub type c_int = i32;

    pub type c_ulong = u64;
    pub type c_long = u64;

    pub type c_uchar = u8;
    pub type c_char = i8;
    pub type c_schar = i8;

    pub type c_ushort = u16;
    pub type c_short = i16;

    pub type c_ulonglong = u64;
    pub type c_longlong = i64;
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub type seL4_RawWord = u64;

#[cfg(target_os = "sel4")]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(not(target_os = "sel4"))]
include!("dummy/bindings.rs");

#[cfg(not(target_os = "sel4"))]
include!("dummy/tls.rs");

#[cfg(test)]
include!(concat!(env!("OUT_DIR"), "/generated_tests.rs"));
