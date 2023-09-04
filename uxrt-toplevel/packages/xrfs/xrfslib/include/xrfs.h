/*
 * XRFS
 *
 * Copyright (c) 2010 Andrew Warkentin
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
#ifndef __XRFS_H
#define __XRFS_H

#include <stdint.h>

/* The basic structures of the xrfs filesystem */

#define XRFS_MINPAGESIZE 256
#define XRFS_MINSIZE 2

#define __mkw(h,l) (((h)&0x00ff)<< 8|((l)&0x00ff))
#define __mkl(h,l) (((h)&0xffff)<<16|((l)&0xffff))
#define __mk4(a,b,c,d) be32_to_cpu(__mkl(__mkw(a,b),__mkw(c,d)))

/*TODO: basically everything*/

#endif
