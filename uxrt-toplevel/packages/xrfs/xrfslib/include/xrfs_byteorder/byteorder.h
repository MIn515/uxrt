#ifndef __XRFS_BYTEORDER_BYTEORDER_H
#define __XRFS_BYTEORDER_BYTEORDER_H 1

#ifndef __STANDALONE_LOADER_INC__
#ifdef __uxrt__
#define __HAVE_ENDIAN_H
#elif defined __linux__
#define __HAVE_ENDIAN_H
#endif
#endif

#ifdef __HAVE_ENDIAN_H
#include <endian.h>
#elif defined __HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif

#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN 4321
#endif
#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1234
#endif


#ifdef __XRFS_BIG_ENDIAN
#define __BYTE_ORDER __BIG_ENDIAN
#else
#ifdef __XRFS_LITTLE_ENDIAN
#define __BYTE_ORDER __LITTLE_ENDIAN
#endif
#endif

#define __BYTEORDER_HAS_U64__
#ifndef __BYTE_ORDER
#error No byte order defined
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
#include <xrfs_byteorder/big_endian.h>
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#include <xrfs_byteorder/little_endian.h>
#else
#error Invalid byte order defined
#endif

#include <xrfs_byteorder/generic.h>
#endif /* __XRFS_BYTEORDER_BYTEORDER_H */
