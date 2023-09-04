/*
 * UX/RT
 *
 * Header for the platform-independent part of the Multiboot loader
 *
 * Copyright (c) 2011-2022 Andrew Warkentin
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
*/
#ifndef __MULTIBOOT_INTERNAL_H
#define __MULTIBOOT_INTERNAL_H

#define MAX_MULTIBOOT_HANDLERS 32

int MULTIBOOT_TEXT_QUALIFIER multiboot_load_kernel_override_name(struct multiboot_exec_params *params, char *const argv[], int argc, char *override_name, const void *kernel, size_t len, size_t mem_len, unsigned flags);

struct multiboot_tag_handler {
        void *func;
        int tag_type;
        int flags;
        int num_found;
};

int MULTIBOOT_TEXT_QUALIFIER multiboot_process_header(struct multiboot_exec_params *params, char *tags, char *end, struct multiboot_tag_handler *handlers, int num_handlers);

#define mb_err_printf printf

#endif /* __MULTIBOOT_INTERNAL_H */
