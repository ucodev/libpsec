#ifndef LIBPSEC_LOW_MD5_GLOBAL_H
#define LIBPSEC_LOW_MD5_GLOBAL_H

#include <stdint.h>

#ifndef LIBPSEC_TYPEDEF_UINTX_T_UINTX
#define LIBPSEC_TYPEDEF_UINTX_T_UINTX
typedef uint16_t UINT2;
typedef uint32_t UINT4;
#endif

#ifndef LIBPSEC_TYPEDEF_UCHAR_POINTER
#define LIBPSEC_TYPEDEF_UCHAR_POINTER
typedef unsigned char *POINTER;
#endif

/*
 * ====================================
 * MOST OF THIS FILE IS PART OF RFC1321
 * ====================================
 *
 * Changes made to this file:
 *  - The top of this file was modified with some additional code and this comment.
 *  - The typedefs for UINT2 and UINT4 were commented. (The new typedefs are at the top of this file)
 *  - The typedefs for POINTER were commented. (The new typedefs are at the top of this file)
 *  - The bottom of this file was modified.
 *
 */

/* GLOBAL.H - RSAREF types and constants
 */

/* PROTOTYPES should be set to one if and only if the compiler supports
  function argument prototyping.
The following makes PROTOTYPES default to 0 if it has not already
  been defined with C compiler flags.
 */
#ifndef PROTOTYPES
#define PROTOTYPES 0
#endif

/* POINTER defines a generic pointer type */
/* typedef unsigned char *POINTER; */

/* UINT2 defines a two byte word */
/* typedef unsigned short int UINT2; */

/* UINT4 defines a four byte word */
/* typedef unsigned long int UINT4; */

/* PROTO_LIST is defined depending on how PROTOTYPES is defined above.
If using PROTOTYPES, then PROTO_LIST returns the list, otherwise it
  returns an empty list.
 */
#if PROTOTYPES
#define PROTO_LIST(list) list
#else
#define PROTO_LIST(list) ()
#endif


/* This comment and the code below this comment is not part of RFC1321 code */
#endif

