#ifndef _XIOS_BYTEORDER_BIG_ENDIAN_H
#define _XIOS_BYTEORDER_BIG_ENDIAN_H
#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN 4321
#endif
#ifndef __BIG_ENDIAN_BITFIELD
#define __BIG_ENDIAN_BITFIELD
#endif

#include <xrfs_byteorder/swab.h>

#define __constant_htonl(x) ((uint32_t)(x))
#define __constant_ntohl(x) ((uint32_t)(x))
#define __constant_htons(x) ((uint16_t)(x))
#define __constant_ntohs(x) ((uint16_t)(x))
#define __constant_cpu_to_le64(x) ___constant_swab64((x))
#define __constant_le64_to_cpu(x) ___constant_swab64((x))
#define __constant_cpu_to_le32(x) ___constant_swab32((x))
#define __constant_le32_to_cpu(x) ___constant_swab32((x))
#define __constant_cpu_to_le16(x) ___constant_swab16((x))
#define __constant_le16_to_cpu(x) ___constant_swab16((x))
#define __constant_cpu_to_be64(x) ((uint64_t)(x))
#define __constant_be64_to_cpu(x) ((uint64_t)(x))
#define __constant_cpu_to_be32(x) ((uint32_t)(x))
#define __constant_be32_to_cpu(x) ((uint32_t)(x))
#define __constant_cpu_to_be16(x) ((uint16_t)(x))
#define __constant_be16_to_cpu(x) ((uint16_t)(x))
#define __cpu_to_le64(x) __swab64((x))
#define __le64_to_cpu(x) __swab64((x))
#define __cpu_to_le32(x) __swab32((x))
#define __le32_to_cpu(x) __swab32((x))
#define __cpu_to_le16(x) __swab16((x))
#define __le16_to_cpu(x) __swab16((x))
#define __cpu_to_be64(x) ((uint64_t)(x))
#define __be64_to_cpu(x) ((uint64_t)(x))
#define __cpu_to_be32(x) ((uint32_t)(x))
#define __be32_to_cpu(x) ((uint32_t)(x))
#define __cpu_to_be16(x) ((uint16_t)(x))
#define __be16_to_cpu(x) ((uint16_t)(x))
#define __cpu_to_le64p(x) __swab64p((x))
#define __le64_to_cpup(x) __swab64p((x))
#define __cpu_to_le32p(x) __swab32p((x))
#define __le32_to_cpup(x) __swab32p((x))
#define __cpu_to_le16p(x) __swab16p((x))
#define __le16_to_cpup(x) __swab16p((x))
#define __cpu_to_be64p(x) (*(uint64_t*)(x))
#define __be64_to_cpup(x) (*(uint64_t*)(x))
#define __cpu_to_be32p(x) (*(uint32_t*)(x))
#define __be32_to_cpup(x) (*(uint32_t*)(x))
#define __cpu_to_be16p(x) (*(uint16_t*)(x))
#define __be16_to_cpup(x) (*(uint16_t*)(x))
#define __cpu_to_le64s(x) __swab64s((x))
#define __le64_to_cpus(x) __swab64s((x))
#define __cpu_to_le32s(x) __swab32s((x))
#define __le32_to_cpus(x) __swab32s((x))
#define __cpu_to_le16s(x) __swab16s((x))
#define __le16_to_cpus(x) __swab16s((x))
#define __cpu_to_be64s(x) do {} while (0)
#define __be64_to_cpus(x) do {} while (0)
#define __cpu_to_be32s(x) do {} while (0)
#define __be32_to_cpus(x) do {} while (0)
#define __cpu_to_be16s(x) do {} while (0)
#define __be16_to_cpus(x) do {} while (0)

#include <xrfs_byteorder/generic.h>

#endif /* _XIOS_BYTEORDER_BIG_ENDIAN_H */
