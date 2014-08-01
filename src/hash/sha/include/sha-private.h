/*
 * ============================
 * THIS FILE IS PART OF RFC4634
 * ============================
 *
 * Copyright (C) The Internet Society (2006).
 *
 * This document is subject to the rights, licenses and restrictions
 * contained in BCP 78, and except as set forth therein, the authors
 * retain all their rights.
 *
 * This document and the information contained herein are provided on an
 * "AS IS" basis and THE CONTRIBUTOR, THE ORGANIZATION HE/SHE REPRESENTS
 * OR IS SPONSORED BY (IF ANY), THE INTERNET SOCIETY AND THE INTERNET
 * ENGINEERING TASK FORCE DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE
 * INFORMATION HEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED
 * WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

/*************************** sha-private.h ***************************/
/********************** See RFC 4634 for details *********************/
#ifndef _SHA_PRIVATE__H
#define _SHA_PRIVATE__H
/*
 * These definitions are defined in FIPS-180-2, section 4.1.
 * Ch() and Maj() are defined identically in sections 4.1.1,
 * 4.1.2 and 4.1.3.
 *
 * The definitions used in FIPS-180-2 are as follows:
 */

#ifndef USE_MODIFIED_MACROS
#define SHA_Ch(x,y,z)        (((x) & (y)) ^ ((~(x)) & (z)))
#define SHA_Maj(x,y,z)       (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#else /* USE_MODIFIED_MACROS */
/*
 * The following definitions are equivalent and potentially faster.
 */

#define SHA_Ch(x, y, z)      (((x) & ((y) ^ (z))) ^ (z))
#define SHA_Maj(x, y, z)     (((x) & ((y) | (z))) | ((y) & (z)))

#endif /* USE_MODIFIED_MACROS */

#define SHA_Parity(x, y, z)  ((x) ^ (y) ^ (z))

#endif /* _SHA_PRIVATE__H */


