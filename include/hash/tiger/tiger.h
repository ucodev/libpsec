/*
 * tiger.h
 *
 * Based on reference implementation from:
 * http://www.cs.technion.ac.il/~biham/Reports/Tiger/ - Eli Biham and Ross Anderson
 *
 * libpsec Changes (by Pedro A. Hortas on 06/09/2014):
 *
 * - Converted constants to settings of tiger_state, allowing generic API access.
 * - Added a _init(), _update() and _finish() function to take full advantage of Merkle-Damgard.
 * - Detect endianness at runtime.
 * - Added configuration options for the number of passes through the *_set_passes() function.
 * - Added a tiger_state type.
 *
 */

#ifndef TIGER_H
#define TIGER_H

#include <stdint.h>

/* Types */
typedef struct tiger_state_struct {
	unsigned char temp[64];
	uint64_t tlen;
	uint64_t mlen;
	uint64_t res[3];
	unsigned int passes;
} tiger_state;

/* Macros */
#define is_littleendian()	(*(unsigned char *) (uint32_t [1]) { 1 })

/* Prototypes */
void tiger_init(tiger_state *state);
void tiger_set_passes(tiger_state *state, unsigned int passes);
void tiger_update(tiger_state *state, const unsigned char *str, uint64_t length);
void tiger_finish(tiger_state *state, unsigned char *digest, int tiger2);

#endif

