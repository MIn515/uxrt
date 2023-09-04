//TODO: add copyright information (this is derived from https://github.com/rust-osdev/multiboot2/tree/main/multiboot2-header/)
//! Module for the helper trait [`StructAsBytes`].
use std::vec::Vec;
use crate::{
    XRFSSuperBlock, BaseTag, AddressTag, PageSizeTag, InfoOffsetTag, ModuleTag, FileHeader
};
use core::mem::size_of;

/// Trait for all tags that helps to create a byte array from the tag.
/// Useful in builders to construct a byte vector that
/// represents the Multiboot2 header with all its tags.
pub(crate) trait StructAsBytes: Sized {
    /// Returns the size in bytes of the struct, as known during compile
    /// time. This doesn't use read the "size" field of tags.
    fn byte_size(&self) -> usize {
        size_of::<Self>()
    }

    /// Returns a byte pointer to the begin of the struct.
    fn as_ptr(&self) -> *const u8 {
        self as *const Self as *const u8
    }

    /// Returns the structure as a vector of its bytes.
    /// The length is determined by [`size`].
    fn struct_as_bytes(&self) -> Vec<u8> {
        let ptr = self.as_ptr();
        let mut vec = Vec::with_capacity(self.byte_size());
        for i in 0..self.byte_size() {
            vec.push(unsafe { *ptr.add(i) })
        }
        vec
    }
    fn struct_as_bytes_aligned(&self, size: usize) -> Vec<u8> {
        let mut bytes = self.struct_as_bytes();
        bytes.resize(size, 0);
        bytes
    }
    fn struct_as_bytes_aligned_with_string(&self, size: usize, string: &String) -> Result<Vec<u8>, ()> {
        let mut bytes = self.struct_as_bytes();
        bytes.extend_from_slice(string.as_bytes());
        //reserve the last byte as a null terminator
        if bytes.len() > size - 1 {
            Err(())
        }else{
            bytes.resize(size, 0);
            Ok(bytes)
        }
    }
}

impl StructAsBytes for XRFSSuperBlock{}
impl StructAsBytes for BaseTag {}
impl StructAsBytes for AddressTag {}
impl StructAsBytes for PageSizeTag {}
impl StructAsBytes for InfoOffsetTag {}
impl StructAsBytes for ModuleTag {}
impl StructAsBytes for FileHeader {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_as_bytes() {
        struct Foobar {
            a: u32,
            b: u8,
            c: u128,
        }
        impl StructAsBytes for Foobar {}
        let foo = Foobar {
            a: 11,
            b: 22,
            c: 33,
        };
        let bytes = foo.struct_as_bytes();
        let foo_from_bytes = unsafe { (bytes.as_ptr() as *const Foobar).as_ref().unwrap() };
        assert_eq!(bytes.len(), size_of::<Foobar>());
        assert_eq!(foo.a, foo_from_bytes.a);
        assert_eq!(foo.b, foo_from_bytes.b);
        assert_eq!(foo.c, foo_from_bytes.c);
    }
}
