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
Copyright © 2014, Markku-Juhani O. Saarinen <mjos@iki.fi> All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
* Neither Markku-Juhani O. Saarinen's name nor NTNU, Kudelski Security, STRIBOB, BLINKER, or the names of any other affiliated Companies, Institutions, Designs or Products may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL MARKKU-JUHANI O. SAARINEN BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

While Kudelski Security and Norwegian University of Science and Technology (NTNU) have been acting as a sponsors of this initiative, Markku-Juhani O. Saarinen is the sole and exclusive owner of the copyright in this software at the exclusion of NTNU and Kudelski Security. NTNU or Kudelski Security have no responsibility whatsoever in such initiative and/or software and IN NO EVENT SHALL KUDELSKI SECURITY OR NTNU BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION).
*/


/*
 * The original code can be downloaded from:
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

