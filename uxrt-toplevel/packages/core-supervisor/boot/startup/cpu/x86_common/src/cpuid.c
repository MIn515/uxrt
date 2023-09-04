/*
 * x86 CPUID-related C functions
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

#include "loader_config.h"
#include "loader_stdlib/stdint.h"
#include "cpu/cpuid.h"

/* Returns true iff the processor supports the features specified in
 * feature_flags. Obviously, this is only meaningful for CPUID levels that
 * access feature flags.*/
int cpuid_check_features(uint32_t level, uint32_t reg, uint32_t feature_flags)
{
	uint32_t regs[CPUID_NUM_REGS];
	/*XXX: look at Linux source for how to use VIA and Transmeta extended flags levels*/
	/* for extended function codes, just return false if they aren't supported */
	if (level >= CPUID_LEVEL_AMD_EXT_PROCESSOR_INFO){
		cpuid(CPUID_LEVEL_HIGHEST_EXT_LEVEL, &regs[CPUID_REG_EAX], &regs[CPUID_REG_EBX], &regs[CPUID_REG_ECX], &regs[CPUID_REG_EDX]);

		if (level > regs[CPUID_REG_EAX]){
			return (0);
		}
	}
	cpuid(level, &regs[CPUID_REG_EAX], &regs[CPUID_REG_EBX], &regs[CPUID_REG_ECX], &regs[CPUID_REG_EDX]);

	return (regs[reg] & feature_flags);
}
