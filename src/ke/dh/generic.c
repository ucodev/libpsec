/*
 * @file generic.c
 * @brief PSEC Library
 *        Key Exhange [DH] interface 
 *
 * Date: 01-09-2014
 *
 * Copyright 2014 Pedro A. Hortas (pah@ucodev.org)
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <gmp.h>

#include "decode.h"
#include "encode.h"
#include "generate.h"
#include "tc.h"

/* RFC3526 values */
static const char g_modp[] = "2";

static const char prime_modp_1536[] =
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
	"670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";

static const char prime_modp_2048[] =
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" 
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
	"15728E5A8AACAA68FFFFFFFFFFFFFFFF";

static const char prime_modp_3072[] =
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
	"43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

static const char prime_modp_4096[] =
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
	"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
	"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
	"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
	"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
	"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
	"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199"
	"FFFFFFFFFFFFFFFF";

static const char prime_modp_6144[] =
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
	"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
	"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
	"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
	"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
	"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
	"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
	"36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD"
	"F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831"
	"179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B"
	"DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF"
	"5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6"
	"D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3"
	"23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
	"CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328"
	"06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C"
	"DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE"
	"12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF";

static const char prime_modp_8192[] =
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
	"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
	"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
	"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
	"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
	"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
	"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
	"36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD"
	"F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831"
	"179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B"
	"DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF"
	"5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6"
	"D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3"
	"23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
	"CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328"
	"06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C"
	"DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE"
	"12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4"
	"38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300"
	"741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F568"
	"3423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9"
	"22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B"
	"4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A"
	"062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A36"
	"4597E899A0255DC164F31CC50846851DF9AB48195DED7EA1"
	"B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92"
	"4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E47"
	"9558E4475677E9AA9E3050E2765694DFC81F56E880B96E71"
	"60C980DD98EDD3DFFFFFFFFFFFFFFFFF";


/* Functions */
static const char *_get_p_modp(int prime_bits) {
	switch (prime_bits) {
		case 1536: return prime_modp_1536;
		case 2048: return prime_modp_2048;
		case 3072: return prime_modp_3072;
		case 4096: return prime_modp_4096;
		case 6144: return prime_modp_6144;
		case 8192: return prime_modp_8192;
		default: return NULL;
	}

	return NULL;
}

unsigned char *dh_init_private_key(unsigned char *priv, size_t priv_size) {
	int errsv = 0, out_alloc = 0;
	mpz_t gmp_s;
	unsigned char *out = NULL, *hex_priv = NULL;

	/* If priv is NULL, out will be dynamically allocated */
	if (!priv)
		out_alloc = 1;

	/* Generate private key */
	if (!(priv = out = generate_bytes_random(priv, priv_size)))
		return NULL;

	/* Encode the random secret in base16 */
	if (!(hex_priv = encode_buffer_base16(NULL, (size_t [1]) { 0 }, priv, priv_size))) {
		errsv = errno;
		if (out_alloc) free(out);
		errno = errsv;
		return NULL;
	}

	/* Initialize gmp value */
	if (mpz_init_set_str(gmp_s, (char *) hex_priv, 16) < 0) {
		errsv = errno;
		mpz_clear(gmp_s);
		encode_destroy(hex_priv);
		if (out_alloc) free(out);
		errno = errsv;
		return NULL;
	}

	/* Free unused memory */
	encode_destroy(hex_priv);

	/* Grant that private key is greater than 1 */
	if (mpz_cmp_ui(gmp_s, 1) <= 0) {
		errsv = errno;
		mpz_clear(gmp_s);
		if (out_alloc) free(out);
		errno = errsv;
		return NULL;
	}

	/* Clear GMP data */
	mpz_clear(gmp_s);

	/* All good */
	return out;
}

unsigned char *dh_compute_public_key(
	unsigned char *pub,
	size_t pub_size,
	const unsigned char *priv,
	size_t priv_size)
{
	int errsv = 0, pub_alloc = 0;
	mpz_t gmp_g, gmp_p, gmp_p_sub_2; /* Generator, prime, prime - 2 */
	mpz_t gmp_r, gmp_s; /* Public result, secret */
	unsigned char *hex_priv = NULL;
	const char *hex_prime = NULL;
	char *hex_pub = NULL;

	/* Retrieve the prime number based on length pbits */
	if (!(hex_prime = _get_p_modp(pub_size << 3))) {
		errno = EINVAL;
		return NULL;
	}

	/* Encode the random secret in base16 */
	if (!(hex_priv = encode_buffer_base16(NULL, (size_t [1]) { 0 }, priv, priv_size)))
		return NULL;

	/* Initialize GMP values */
	if (mpz_init_set_str(gmp_g, g_modp, 10) < 0) {
		errsv = errno;
		mpz_clear(gmp_g);
		encode_destroy(hex_priv);
		errno = errsv;
		return NULL;
	}

	if (mpz_init_set_str(gmp_p, hex_prime, 16) < 0) {
		errsv = errno;
		mpz_clear(gmp_g);
		mpz_clear(gmp_p);
		encode_destroy(hex_priv);
		errno = errsv;
		return NULL;
	}

	if (mpz_init_set_str(gmp_s, (char *) hex_priv, 16) < 0) {
		errsv = errno;
		mpz_clear(gmp_g);
		mpz_clear(gmp_p);
		mpz_clear(gmp_s);
		encode_destroy(hex_priv);
		errno = errsv;
		return NULL;
	}

	mpz_init(gmp_r);
	mpz_init(gmp_p_sub_2);

	/* Free unused memory */
	encode_destroy(hex_priv);

	/* Grant that exp is greater than 1 */
	if (mpz_cmp_ui(gmp_s, 1) <= 0) {
		mpz_clear(gmp_g);
		mpz_clear(gmp_p);
		mpz_clear(gmp_p_sub_2);
		mpz_clear(gmp_s);
		mpz_clear(gmp_r);
		errno = EINVAL;
		return NULL;
	}

	/* Compute prime - 2 */
	mpz_sub_ui(gmp_p_sub_2, gmp_p, 2);

	/* Grant that exp is lesser than prime - 1 */
	if (mpz_cmp(gmp_s, gmp_p_sub_2) > 0) {
		mpz_clear(gmp_g);
		mpz_clear(gmp_p);
		mpz_clear(gmp_p_sub_2);
		mpz_clear(gmp_s);
		mpz_clear(gmp_r);
		errno = EINVAL;
		return NULL;
	}

	/* Compute public result */
	mpz_powm_sec(gmp_r, gmp_g, gmp_s, gmp_p);

	/* Clear unused GMP data */
	mpz_clear(gmp_g);
	mpz_clear(gmp_p);
	mpz_clear(gmp_p_sub_2);
	mpz_clear(gmp_s);

	/* Convert 'r' to base16 */
	if (!(hex_pub = mpz_get_str(NULL, 16, gmp_r))) {
		errsv = errno;
		mpz_clear(gmp_r);
		errno = errsv;
		return NULL;
	}

	/* Clear unused GMP data */
	mpz_clear(gmp_r);

	/* If out is NULL, allocate enough space to hold the decoded result */
	if (!pub) {
		if (!(pub = malloc(pub_size))) {
			errsv = errno;
			free(hex_pub);
			errno = errsv;
			return NULL;
		}

		pub_alloc = 1;
	}

	/* Reset out memory */
	tc_memset(pub, 0, pub_size);

	/* Decode 'hex_result' */
	if (!(decode_buffer_base16(pub, (size_t [1]) { 0 }, (unsigned char *) hex_pub, strlen(hex_pub)))) {
		errsv = errno;
		free(hex_pub);
		if (pub_alloc) free(pub);
		errno = errsv;
		return NULL;
	}

	/* Free unused memory */
	free(hex_pub);

	/* All good */
	return pub;
}

unsigned char *dh_compute_shared_key(
	unsigned char *shared,
	const unsigned char *pub,
	size_t pub_size,
	const unsigned char *priv,
	size_t priv_size)
{
	int errsv = 0, shared_alloc = 0;
	mpz_t gmp_p, gmp_p_sub_2;	/* Prime */
	mpz_t gmp_k, gmp_r, gmp_s;	/* Key, public result */
	const char *hex_prime = NULL;
	char *hex_shared = NULL;
	unsigned char *hex_pub = NULL, *hex_priv = NULL;

	/* Retrieve the prime number based on length pbits */
	if (!(hex_prime = _get_p_modp(pub_size << 3))) {
		errno = EINVAL;
		return NULL;
	}

	/* Encode the public result in base16 */
	if (!(hex_pub = encode_buffer_base16(NULL, (size_t [1]) { 0 }, pub, pub_size)))
		return NULL;

	/* Encode the secret in base16 */
	if (!(hex_priv = encode_buffer_base16(NULL, (size_t [1]) { 0 }, priv, priv_size))) {
		encode_destroy(hex_pub);
		return NULL;
	}

	/* Initialize GMP values */
	if (mpz_init_set_str(gmp_p, hex_prime, 16) < 0) {
		errsv = errno;
		mpz_clear(gmp_p);
		encode_destroy(hex_pub);
		encode_destroy(hex_priv);
		errno = errsv;
		return NULL;
	}

	if (mpz_init_set_str(gmp_r, (char *) hex_pub, 16) < 0) {
		errsv = errno;
		mpz_clear(gmp_p);
		mpz_clear(gmp_r);
		encode_destroy(hex_pub);
		encode_destroy(hex_priv);
		errno = errsv;
		return NULL;
	}

	if (mpz_init_set_str(gmp_s, (char *) hex_priv, 16) < 0) {
		errsv = errno;
		mpz_clear(gmp_p);
		mpz_clear(gmp_r);
		mpz_clear(gmp_s);
		encode_destroy(hex_pub);
		encode_destroy(hex_priv);
		errno = errsv;
		return NULL;
	}

	mpz_init(gmp_k);
	mpz_init(gmp_p_sub_2);

	/* Free unused memory */
	encode_destroy(hex_pub);
	encode_destroy(hex_priv);

	/* Grant that base is greater than 1 */
	if (mpz_cmp_ui(gmp_r, 1) <= 0) {
		mpz_clear(gmp_k);
		mpz_clear(gmp_p);
		mpz_clear(gmp_p_sub_2);
		mpz_clear(gmp_r);
		mpz_clear(gmp_s);
		errno = EINVAL;
		return NULL;
	}

	/* Grant that exp is greater than 1 */
	if (mpz_cmp_ui(gmp_s, 1) <= 0) {
		mpz_clear(gmp_k);
		mpz_clear(gmp_p);
		mpz_clear(gmp_p_sub_2);
		mpz_clear(gmp_r);
		mpz_clear(gmp_s);
		errno = EINVAL;
		return NULL;
	}

	/* Compute prime - 2 */
	mpz_sub_ui(gmp_p_sub_2, gmp_p, 2);

	/* Grant that exp is lesser than prime - 1 */
	if (mpz_cmp(gmp_s, gmp_p_sub_2) > 0) {
		mpz_clear(gmp_k);
		mpz_clear(gmp_p);
		mpz_clear(gmp_p_sub_2);
		mpz_clear(gmp_s);
		mpz_clear(gmp_r);
		errno = EINVAL;
		return NULL;
	}

	/* Grant that base is lesser than prime - 1 */
	if (mpz_cmp(gmp_r, gmp_p_sub_2) > 0) {
		mpz_clear(gmp_k);
		mpz_clear(gmp_p);
		mpz_clear(gmp_p_sub_2);
		mpz_clear(gmp_s);
		mpz_clear(gmp_r);
		errno = EINVAL;
		return NULL;
	}

	/* Compute public result */
	mpz_powm_sec(gmp_k, gmp_r, gmp_s, gmp_p);

	/* Clear unused GMP data */
	mpz_clear(gmp_p);
	mpz_clear(gmp_p_sub_2);
	mpz_clear(gmp_r);
	mpz_clear(gmp_s);

	/* Convert 'r' to base16 */
	if (!(hex_shared = mpz_get_str(NULL, 16, gmp_k))) {
		errsv = errno;
		mpz_clear(gmp_k);
		errno = errsv;
		return NULL;
	}

	/* Clear unused GMP data */
	mpz_clear(gmp_k);

	/* If out is NULL, allocate enough space to hold the decoded result */
	if (!shared) {
		if (!(shared = malloc(pub_size))) {
			errsv = errno;
			free(hex_shared);
			errno = errsv;
			return NULL;
		}

		shared_alloc = 1;
	}

	/* Reset out memory */
	tc_memset(shared, 0, pub_size);

	/* Decode 'hex_result' */
	if (!(decode_buffer_base16(shared, (size_t [1]) { 0 }, (unsigned char *) hex_shared, strlen(hex_shared)))) {
		errsv = errno;
		free(hex_shared);
		if (shared_alloc) free(shared);
		errno = errsv;
		return NULL;
	}

	/* Free unused memory */
	free(hex_shared);

	/* All Good */
	return shared;
}

