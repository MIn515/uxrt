/*
 * Copyright (c) 2018-2022 Andrew Warkentin
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2 or (at your option) any later
 * version. Note that NO WARRANTY is provided. See "LICENSE-GPLv2" for
 * details.
 */

use core::str::FromStr;
use alloc::string::String;

use multiboot2::BaseModuleTag;

pub struct MBIHandler {
	mbi_vaddr: usize,
	mbi_paddr: usize,
	mbi: multiboot2::BootInformation,
	fs_start_addr: usize,
	fs_end_addr: usize,
	pub(crate) user_start_addr: usize,
	pub(crate) user_end_addr: usize,
	pub(crate) root_server_end_addr: usize,
	pub(crate) kernel_cmdline: String,
	pub(crate) proc_cmdline: String,
}

impl MBIHandler {
	fn convert_mbi_addr(&mut self, addr: usize) -> usize{
		if self.mbi_vaddr > self.mbi_paddr {
			return addr + (self.mbi_vaddr - self.mbi_paddr);
		}else{

			return addr - (self.mbi_paddr - self.mbi_vaddr);
		}

	}
	fn process_cmdline(&mut self, cmdline: &str) {
		info!("kernel command line: {}", cmdline);
		self.kernel_cmdline = String::from_str(cmdline).unwrap();
	}
	fn process_supervisor_image(&mut self) {
		info!("fs_start_addr: {:x}", self.fs_start_addr);
		info!("fs_end_addr: {:x}", self.fs_end_addr);
	}

	fn process_module(&mut self, module: &dyn multiboot2::BaseModuleTag){
		info!("name: {}", module.name());
		info!("start paddr: {:x}", module.start_address());
		info!("end paddr: {:x}", module.end_address());

		let start_addr = self.convert_mbi_addr(module.start_address() as usize);
		let end_addr = self.convert_mbi_addr(module.end_address() as usize);

		info!("start vaddr: {:x}", start_addr);
		info!("end vaddr: {:x}", end_addr);

		if start_addr < self.fs_start_addr || end_addr > self.fs_end_addr {
			panic!("module outside main area of supervisor image");
		}

		info!("-");
	}

	pub fn process_mbi(&mut self) {
		info!("multiboot:");
		info!("mbi_vaddr: {:x}", self.mbi_vaddr);
		info!("mbi_paddr: {:x}", self.mbi_paddr);
		//parse the kernel command line
		let cmdline = self.mbi.command_line_tag();
		match cmdline {
			Some(ref cmdline_tag) => self.process_cmdline(cmdline_tag.command_line()),
			None => panic!("bootloader did not pass a command line tag"),
		}

		//look up the process server module to get the end
		//address of the process server, which is the start
		//of the main area of the supervisor image that
		//contains all the files in the image that are used by
		//user programs (i.e. all files in the image except the
		//kernel and process server)
		let mut exec_module_tags = self.mbi.exec_module_tags();
		let proc_module = exec_module_tags.next();
		if exec_module_tags.count() != 0 {
			panic!("multiple preloaded executable module tags present in MBI (only the process server should be preloaded)");
		}
		match proc_module {
			Some(ref base_module) => {
				let module: &&multiboot2::ExecModuleTag = base_module;
				self.fs_start_addr = self.convert_mbi_addr(module.padding_end() as usize);
				self.user_start_addr = self.convert_mbi_addr(base_module.start_address() as usize);
				self.root_server_end_addr = self.convert_mbi_addr(base_module.end_address() as usize);
				self.proc_cmdline = String::from_str(module.name()).unwrap();
			},
			None => panic!("no preloaded executable modules present in MBI (the process server must be loaded as a preloaded executable)"),
		}

		self.user_end_addr = self.mbi.end_address();

		//look up the supervisor image tag to get the image end
		//address
		let mut fs_module_tags = self.mbi.fs_image_module_tags();
		let supervisor_img_module = fs_module_tags.next();
		if fs_module_tags.count() != 0 {
			panic!("multiple boot FS image module tags present in MBI");
		}
		match supervisor_img_module {
			Some(ref module) => {
				self.fs_end_addr = self.convert_mbi_addr(module.end_address() as usize);
			},
			None => panic!("no boot FS image present in MBI"),
		}

		self.process_supervisor_image();
		//process the regular modules
		info!("multiboot modules:");
		info!("---");
		let mut module_found = false;
		for module in self.mbi.module_tags(){
			self.process_module(module);
			module_found = true;
		}
		if !module_found {
			panic!("no regular modules present in MBI");
		}
		info!("---");
	}
	pub fn new(mbi_vaddr: usize, mbi_paddr: usize) -> MBIHandler {
		unsafe {
			let mbi = multiboot2::load(mbi_vaddr);
			let mut handler = MBIHandler {
				mbi_vaddr, 
				mbi_paddr, 
				mbi, 
				fs_start_addr: 0, 
				fs_end_addr: 0, 
				user_start_addr: 0, 
				user_end_addr: 0, 
				root_server_end_addr: 0,
				kernel_cmdline: Default::default(),
				proc_cmdline: Default::default(),
			};
			handler.process_mbi();
			handler
		}
	}
}

pub fn process_bootinfo(bootinfo: &'static sel4_sys::seL4_BootInfo) -> MBIHandler {
	info!("------------- bootinfo -------------");
	info!("bootinfo.ipcBuffer = {:p}", bootinfo.ipcBuffer);
	info!("bootinfo.empty.start = {}", bootinfo.empty.start);
	info!("bootinfo.empty.end = {}", bootinfo.empty.end);

	info!(
		"bootinfo.userImageFrames.start = {}",
		bootinfo.userImageFrames.start
	);
	info!(
		"bootinfo.userImageFrames.end = {}",
		bootinfo.userImageFrames.end
	);

	info!("bootinfo.untyped.start = {}", bootinfo.untyped.start);
	info!("bootinfo.untyped.end = {}", bootinfo.untyped.end);

	info!("bootinfo.untypedList");
	info!(
		"  length = {}",
		bootinfo.untyped.end - bootinfo.untyped.start
	);

	for i in bootinfo.untyped.start..bootinfo.untyped.end {
		let index: usize = (i - bootinfo.untyped.start) as usize;
		info!(
			"  [{} | {}] paddr = 0x{:X} - size_bits = {} - is_device = {}",
			index,
			i,
			bootinfo.untypedList[index].paddr,
			bootinfo.untypedList[index].sizeBits,
			bootinfo.untypedList[index].isDevice
		);
	}
	info!("bootinfo.extraLen = {}", bootinfo.extraLen);

	let bootinfo_iter = unsafe { sel4::bootinfo_extras(bootinfo) };
	let mut mbi_header = None;

	for header in bootinfo_iter {
		match header {
			sel4::BootInfoExtra::X86_mbi2_pt(mbi) => { 
				mbi_header = Some(mbi.clone());
			},
			_ => {},
		}
	}

	match mbi_header {
		Some(mbi) => {
			let vaddr = mbi.mbi_vaddr as usize;
			let paddr = mbi.mbi_paddr as usize;
			info!("mbi: vaddr: 0x{:x}, paddr: 0x{:x}", vaddr, paddr);
			let handler = MBIHandler::new(vaddr, paddr);
			info!("--------------------------\n");

			handler
		},
		None => panic!("kernel did not provide Multiboot info pointer"),
	}

}

/* vim: set softtabstop=8 tabstop=8 noexpandtab: */
