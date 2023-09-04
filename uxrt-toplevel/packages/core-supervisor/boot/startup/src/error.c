/*
 * Main function of the platform-independent part of the loader
 *
 * UX/RT
 *
 * Copyright (c) 2010-2022 Andrew Warkentin
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

#include <loader_stdlib/errno.h>
#include <loader_stdlib/stdio.h>
#ifndef STDIO_ERRSTR_IMPLEMENTED
#include "core/platform/errstr.h"

const char *loader_strerror(int errnum)
{
	if (errnum > sys_nerr){
		return ("(unknown)");
	}else{
		return (sys_errlist[errnum]);
	}
}
void loader_perror(const char *str)
{
	printf("%s: %s\n", str, loader_strerror(errno));
}
#endif
