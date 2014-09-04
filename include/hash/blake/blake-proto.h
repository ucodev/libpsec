#ifndef BLAKE_PROTO_H
#define BLAKE_PROTO_H

#include "blake.h"

/* Definitions */
#define U8TO32_BIG(p)					      \
  (((uint32_t)((p)[0]) << 24) | ((uint32_t)((p)[1]) << 16) |  \
   ((uint32_t)((p)[2]) <<  8) | ((uint32_t)((p)[3])      ))

#define U32TO8_BIG(p, v)				        \
  (p)[0] = (uint8_t)((v) >> 24); (p)[1] = (uint8_t)((v) >> 16); \
  (p)[2] = (uint8_t)((v) >>  8); (p)[3] = (uint8_t)((v)      );

#define U8TO64_BIG(p) \
  (((uint64_t)U8TO32_BIG(p) << 32) | (uint64_t)U8TO32_BIG((p) + 4))

#define U64TO8_BIG(p, v)		      \
  U32TO8_BIG((p),     (uint32_t)((v) >> 32)); \
  U32TO8_BIG((p) + 4, (uint32_t)((v)      ));

/* Prototypes */
void blake224_init(state224 *S);
void blake224_update(state224 *S, const uint8_t *in, uint64_t inlen);
void blake224_final(state224 *S, uint8_t *out);
void blake256_init(state256 *S);
void blake256_update(state256 *S, const uint8_t *in, uint64_t inlen);
void blake256_final(state256 *S, uint8_t *out);void blake224_init(state224 *S);
void blake384_init(state384 *S);
void blake384_update(state384 *S, const uint8_t *in, uint64_t inlen);
void blake384_final(state384 *S, uint8_t *out);void blake224_init(state224 *S);
void blake512_init(state512 *S);
void blake512_update(state512 *S, const uint8_t *in, uint64_t inlen);
void blake512_final(state512 *S, uint8_t *out);

#endif
