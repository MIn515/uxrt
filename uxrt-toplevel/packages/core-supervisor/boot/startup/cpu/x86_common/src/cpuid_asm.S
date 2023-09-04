/*
 * x86 CPUID-related assembly functions
 *
 * RT/XH
 *
 * Copyright (c) 2011 Andrew Warkentin
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

/* void cpuid(uint32_t function_code, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
 * 
 * Executes cpuid with function_code in EAX, and sets the register arguments to the values in their respective registers*/
cpuid:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%esi
	pushl	%ebx
	movl	12(%ebp), %eax
	movl	8(%ebp), %edx
	movl	%edx, (%eax)
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	cpuid
	movl	12(%ebp), %esi
	movl	%eax, (%esi)
	movl	16(%ebp), %eax
	movl	%ebx, (%eax)
	movl	20(%ebp), %eax
	movl	%ecx, (%eax)
	movl	24(%ebp), %eax
	movl	%edx, (%eax)
	popl	%ebx
	popl	%esi
	popl	%ebp
	ret
