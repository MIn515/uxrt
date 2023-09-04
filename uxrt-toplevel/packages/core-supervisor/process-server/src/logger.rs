/*
 * Copyright (c) 2018 Andrew Warkentin
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2 or (at your option) any later
 * version. Note that NO WARRANTY is provided. See "LICENSE-GPLv2" for
 * details.
 *
 */
use log::{Record, Level, Metadata, SetLoggerError, LevelFilter};

use crate::job::thread::get_current_tid;

static LOG_PROCESS_NAME: &'static str = "proc";

struct Logger;

impl log::Log for Logger {
	fn enabled(&self, metadata: &Metadata) -> bool {
		metadata.level() <= Level::Debug
	}

	fn log(&self, record: &Record) {
		if self.enabled(record.metadata()) {
			print!("{}", LOG_PROCESS_NAME);
			print!(" ({})", get_current_tid());
			println!(": {}", record.args());
		}
	}
	fn flush(&self) {}
}


static LOGGER: Logger = Logger;

pub fn init() -> Result<(), SetLoggerError> {
	log::set_logger(&LOGGER)
		.map(|()| log::set_max_level(LevelFilter::Info))
}

/* vim: set softtabstop=8 tabstop=8 noexpandtab: */
