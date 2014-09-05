/*
 *  gosthash.h 
 *  21 Apr 1998  Markku-Juhani Saarinen <mjos@ssh.fi>
 * 
 *  GOST R 34.11-94, Russian Standard Hash Function 
 *  header with function prototypes.
 *
 *  Copyright (c) 1998 SSH Communications Security, Finland
 *  All rights reserved.                    
 */

/* libpsec Changes (by Pedro A. Hortas on 05/09/2014):
 *
 * - S-Boxes are now fully computed into static variables in the gosthash_sbox.h file
 * - gosthash_init() function was removed.
 * - uint32_t type was replaced by uint32_t
 *
 */

/*
 * The original code (before libpsec changes) is in the public domain.
 *
 * It can be downloaded from:
 *
 * http://www.autochthonous.org/crypto/gosthash.tar.gz
 *
 */

#ifndef GOSTHASH_H
#define GOSTHASH_H

#include <stdint.h>
#include <stdlib.h>

/* State structure */

typedef struct 
{
  uint32_t sum[8];
  uint32_t hash[8];
  uint32_t len[8];
  unsigned char partial[32];
  size_t partial_bytes;  
} GostHashCtx;
  
/* Clear the state of the given context structure. */

void gosthash_reset(GostHashCtx *ctx);  

/* Mix in len bytes of data for the given buffer. */

void gosthash_update(GostHashCtx *ctx, const unsigned char *buf, size_t len);

/* Compute and save the 32-byte digest. */

void gosthash_final(GostHashCtx *ctx, unsigned char *digest);

#endif /* GOSTHASH_H */

