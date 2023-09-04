/*
 * Copyright (c) 2022 Andrew Warkentin
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2 or (at your option) any later
 * version. Note that NO WARRANTY is provided. See "LICENSE-GPLv2" for
 * details.
 *
 * This is the base fault handler. This dispatches faults to the appropriate
 * driver if they can be handled and panics otherwise
 */

use sel4::{
	FaultMsg,
	RecvToken,
};

use sel4_thread::WrappedThread;

use crate::job::get_job_tree;

use super::{
	decode_fault_badge,
	get_root_alloc,
};

static FAULT_HANDLER: FaultHandler = FaultHandler::new();

///Gets the fault handler
pub fn get_fault_handler() -> &'static FaultHandler {
	&FAULT_HANDLER
}

pub struct FaultHandler {
}

///Global handler for thread faults
impl FaultHandler {
	///Create a new `FaultHandler`
	const fn new() -> FaultHandler {
		FaultHandler {}
	}
	///Initializes the fault handler
	///
	///This creates a thread that runs the main_loop() method
	pub fn init(&self){
		info!("initializing fault handler");
		let fault_handler = get_job_tree().new_root_thread().expect("could not create fault handler thread");
		fault_handler.write().set_name("fault_handler");
		fault_handler.write().run(move ||{
			get_fault_handler().main_loop();
		}).expect("failed to start fault handler thread");
	}
	///Main loop of the fault handler
	fn main_loop(&self) -> ! {
		let fault_endpoint = get_root_alloc().get_orig_fault_endpoint();
		loop {
			let (fault, msg) = FaultMsg::recv_refuse_reply(fault_endpoint);
			self.handle_fault(fault, msg);
		}
	}
	///Handles an individual fault.
	///
	///Currently just panics the entire system
	fn handle_fault(&self, fault: Option<FaultMsg>, msg: RecvToken){
		let (pid, tid) = decode_fault_badge(msg.badge);
		panic!("unhandled fault in process {} thread {}: {:?}", pid, tid, fault);
		//TODO: handle ThreadFDSpace faults here (check if the fault is in the thread's FDSpace array here and page in the dummy page, passing it on (i.e. just panicking at the moment) otherwise)
	}
}

/* vim: set softtabstop=8 tabstop=8 noexpandtab: */
