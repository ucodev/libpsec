#include <stdint.h>

typedef uint16_t UINT2;
typedef uint32_t UINT4;

/*
 * ============================
 * THIS FILE IS PART OF RFC1320
 * ============================
 *
 * Changes made to this file:
 *  - The top of this file was modified with some additional code and this comment.
 *  - The typedefs for UINT2 and UINT4 were commented. (The new typedefs are at the top of this file)
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
typedef unsigned char *POINTER;

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

