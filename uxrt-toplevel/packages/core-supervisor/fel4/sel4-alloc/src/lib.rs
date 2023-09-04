// Copyright 2019-2021 Andrew Warkentin
//
// Based on code from Robigalia:
//
// Copyright 2016 Robigalia Project Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//#![doc(html_root_url = "https://doc.robigalia.org/")]
#![no_std]
#![feature(thread_local)]
#![feature(allocator_api)]
#![cfg_attr(feature = "cargo-clippy", allow(too_many_arguments, inline_always))]

//! Resource allocation.
//!
//! See the README for design notes.
//!
//! This crate is analogous to libsel4allocman, libsel4vka, libsel4vspace, and portions of
//! libsel4utils from the seL4 C libraries.

#[allow(unused)]
#[macro_use]
extern crate sel4;
extern crate sel4_sys;
extern crate sel4_start;
extern crate bitmap;
#[macro_use]
extern crate intrusive_collections;
extern crate alloc;
#[macro_use]
extern crate failure;
extern crate sparse_array;
extern crate usync;
extern crate slab_allocator_core;
extern crate custom_slab_allocator;
#[macro_use]
extern crate log;

use core::fmt;
use custom_slab_allocator::CustomSlabAllocator;

#[allow(non_camel_case_types)]
#[cfg(all(target_arch = "arm", target_pointer_width = "32"))]
pub type seL4_ARCH_VMAttributes = sel4_sys::seL4_ARM_VMAttributes;
#[allow(non_camel_case_types)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub type seL4_ARCH_VMAttributes = sel4_sys::seL4_X86_VMAttributes;

/// `CSpace` management
pub mod cspace;
use cspace::CSpaceManager;

pub mod utspace;
use utspace::UTSpaceManager;

mod dummy;

/// `VSpace` management
pub mod vspace;
pub use vspace::{
    VSpaceError,
    VSpaceManager,
    VSpaceReservation,
};

pub mod bootstrap;

#[macro_use]
pub mod heap;

/// Resource allocator bundle.
pub trait AllocatorBundle {
    type CSpace: CSpaceManager + fmt::Debug;
    type UTSpace: UTSpaceManager + fmt::Debug;
    type VSpace: VSpaceManager + fmt::Debug;

    ///Get the CSpace manager
    fn cspace(&self) -> &Self::CSpace;
    ///Get the UTSpace manager
    fn utspace(&self) -> &Self::UTSpace;
    ///Get the VSpace manager
    fn vspace(&self) -> &Self::VSpace;

    ///Acquire the recursion lock before allocating, refilling as necessary.
    ///
    ///The recursion lock does not provide any thread safety. The heap module 
    ///provides a LockedAllocatorBundle struct that makes the AllocatorBundle
    ///used by the heap thread-safe by wrapping it in a mutex.
    fn lock_alloc(&self) -> Result<(), ()>;
    ///Acquire the recursion lock before deallocating, refilling as necessary.
    fn lock_dealloc(&self) -> Result<(), ()>;
    ///Acquire the recursion lock before allocating without refilling.
    fn lock_alloc_no_refill(&self) -> Result<(), ()>;
    ///Acquire the recursion lock before allocating without refilling.
    fn lock_dealloc_no_refill(&self) -> Result<(), ()>;
    ///Refills any allocators if necessary
    fn refill(&self) -> Result<(), ()>;
    ///Drops any internal deallocated objects
    fn drop_unused(&self) -> Result<(), ()>;
    ///Releases the recursion lock after allocating without dropping internal 
    ///deallocated objects
    fn unlock_alloc_no_drop(&self) -> Result<(), ()>;
    ///Releases the recursion lock after deallocating without dropping
    ///internal deallocated objects
    fn unlock_dealloc_no_drop(&self) -> Result<(), ()>;
    ///Releases the recursion lock after allocating, dropping internal 
    ///deallocated objects as necessary
    fn unlock_alloc(&self) -> Result<(), ()>;
    ///Releases the recursion lock after allocating, dropping internal 
    ///deallocated objects as necessary
    fn unlock_dealloc(&self) -> Result<(), ()>;

    fn minimum_slots(&self) -> usize;
    fn minimum_untyped(&self) -> usize;
    fn minimum_vspace(&self) -> usize;
}

impl<C, UT, V> AllocatorBundle for (C, UT, V)
where
    C: CSpaceManager + fmt::Debug,
    UT: UTSpaceManager + fmt::Debug,
    V: VSpaceManager + fmt::Debug,
{
    type CSpace = C;
    type UTSpace = UT;
    type VSpace = V;

    fn cspace(&self) -> &C {
        &self.0
    }

    fn utspace(&self) -> &Self::UTSpace {
        &self.1
    }

    fn vspace(&self) -> &Self::VSpace {
        &self.2
    }

    fn lock_alloc(&self) -> Result<(), ()>{
        match self.cspace().lock_alloc(self){
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }

    fn lock_dealloc(&self) -> Result<(), ()>{
        match self.cspace().lock_dealloc(self){
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }

    fn lock_alloc_no_refill(&self) -> Result<(), ()> {
        match self.cspace().lock_alloc_no_refill(self){
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }

    fn lock_dealloc_no_refill(&self) -> Result<(), ()> {
        match self.cspace().lock_dealloc_no_refill(self){
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }

    fn refill(&self) -> Result<(), ()> {
        match self.cspace().refill(self){
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }


    fn drop_unused(&self) -> Result<(), ()> {
        match self.cspace().drop_unused(self){
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }

    fn unlock_alloc_no_drop(&self) -> Result<(), ()> {
        match self.cspace().unlock_alloc_no_drop(self){
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }


    fn unlock_dealloc_no_drop(&self) -> Result<(), ()>{
        match self.cspace().unlock_dealloc_no_drop(self){
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }

    fn unlock_alloc(&self) -> Result<(), ()>{
        match self.cspace().unlock_alloc(self){
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }

    fn unlock_dealloc(&self) -> Result<(), ()>{
        match self.cspace().unlock_dealloc(self){
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }

    fn minimum_slots(&self) -> usize {
        self.cspace().minimum_slots() + self.utspace().minimum_slots() +
            self.vspace().minimum_slots()
    }

    fn minimum_untyped(&self) -> usize {
        self.cspace().minimum_untyped() + self.utspace().minimum_untyped() +
            self.vspace().minimum_untyped()
    }

    fn minimum_vspace(&self) -> usize {
        self.cspace().minimum_vspace() + self.utspace().minimum_vspace() +
            self.vspace().minimum_vspace()
    }
}

pub fn add_custom_slabs<A: CustomSlabAllocator>(alloc: &A) -> Result<(), ()>{
    cspace::add_custom_slabs(alloc)?;
    utspace::add_custom_slabs(alloc)?;
    vspace::add_custom_slabs(alloc)
}
