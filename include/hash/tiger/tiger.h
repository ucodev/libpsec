/*
 * tiger.h
 *
 * Based on reference implementation from:
 * http://www.cs.technion.ac.il/~biham/Reports/Tiger/ - Eli Biham and Ross Anderson
 *
 * libpsec Changes (by Pedro A. Hortas on 06/09/2014):
 *
 * - Converted constants to settings of haval_state, allowing generic API access.
 * - Detect endianness at runtime.
 * - Added configuration options for number of passes through *_set_passes() function.
 * - Added a tiger_state type.
 *
 */

#ifndef TIGER_H
#define TIGER_H

#include <stdint.h>

/* Types */
typedef uint64_t word64;
typedef uint32_t word32;
typedef unsigned char byte;

typedef struct tiger_state_struct {
	word64 res[3];
	unsigned int passes;
} tiger_state;

/* Macros */
#define is_littleendian()	(*(unsigned char *) (uint32_t [1]) { 1 })

/* Prototypes */
void tiger_init(tiger_state *state);
void tiger_set_passes(tiger_state *state, unsigned int passes);
void tiger_update(tiger_state *state, const unsigned char *str, word64 length);
void tiger_finish(tiger_state *state, unsigned char *digest);

#endif

