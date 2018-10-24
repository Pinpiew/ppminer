// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Modified for CPUminer by Lucas Jones
#include "ppminer-config.h"
#include "algo-gate-api.h"

#if defined(__AES__)
  #include "algo/groestl/aes_ni/hash-groestl256.h"
#else
#include "crypto/c_groestl.h"
#endif
#include "crypto/c_keccak.h"
#include "crypto/c_blake256.h"
#include "crypto/c_jh.h"
#include "crypto/c_skein.h"
#include "cryptonight.h"
#include "soft_aes.h"

#include <memory.h>
#include <stdio.h>
#include <fenv.h>

typedef enum
{
	invalid_algo = 0,
	cryptonight = 1,
	cryptonight_lite = 2,
	cryptonight_monero = 3,
	cryptonight_heavy = 4,
	cryptonight_aeon = 5,
	cryptonight_ipbc = 6, // equal to cryptonight_aeon with a small tweak in the miner code
	cryptonight_stellite = 7, //equal to cryptonight_monero but with one tiny change
	cryptonight_masari = 8, //equal to cryptonight_monero but with less iterations, used by masari
	cryptonight_haven = 9, // equal to cryptonight_heavy with a small tweak
	cryptonight_bittube2 = 10, // derived from cryptonight_heavy with own aes-round implementation and minor other tweaks
	cryptonight_monero_v8 = 11,
	cryptonight_num
} algo_cn;

typedef struct {
	uint8_t hash_state[224]; // Need only 200, explicit align
	uint8_t _ALIGN(16) long_state[MEMORY * 2];;
	uint8_t ctx_info[24]; //Use some of the extra memory for flags
} cryptonight_ctx;

bool cryptonightV7;

const size_t CRYPTONIGHT_LITE_MEMORY = 1 * 1024 * 1024;
const uint32_t CRYPTONIGHT_LITE_MASK = 0xFFFF0;
const uint32_t CRYPTONIGHT_LITE_ITER = 0x40000;
const size_t CRYPTONIGHT_MEMORY = 2 * 1024 * 1024;
const uint32_t CRYPTONIGHT_MASK = 0x1FFFF0;
const uint32_t CRYPTONIGHT_ITER = 0x80000;
const size_t CRYPTONIGHT_HEAVY_MEMORY = 4 * 1024 * 1024;
const uint32_t CRYPTONIGHT_HEAVY_MASK = 0x3FFFF0;
const uint32_t CRYPTONIGHT_HEAVY_ITER = 0x40000;
const uint32_t CRYPTONIGHT_MASARI_ITER = 0x40000;

#ifdef __GNUC__
#include <x86intrin.h>
static inline uint64_t _umul128(uint64_t a, uint64_t b, uint64_t* hi)
{
	unsigned __int128 r = (unsigned __int128)a * (unsigned __int128)b;
	*hi = r >> 64;
	return (uint64_t)r;
}

#else
#include <intrin.h>
#endif // __GNUC__

inline size_t cn_select_memory(algo_cn algo)
{
	switch(algo)
	{
	case cryptonight_stellite:
	case cryptonight_monero:
	case cryptonight_monero_v8:
	case cryptonight_masari:
	case cryptonight:
		return CRYPTONIGHT_MEMORY;
	case cryptonight_ipbc:
	case cryptonight_aeon:
	case cryptonight_lite:
		return CRYPTONIGHT_LITE_MEMORY;
	case cryptonight_bittube2:
	case cryptonight_haven:
	case cryptonight_heavy:
		return CRYPTONIGHT_HEAVY_MEMORY;
	default:
		return 0;
	}
}

inline size_t cn_select_mask(algo_cn algo)
{
	switch(algo)
	{
	case cryptonight_stellite:
	case cryptonight_monero:
	case cryptonight_monero_v8:
	case cryptonight_masari:
	case cryptonight:
		return CRYPTONIGHT_MASK;
	case cryptonight_ipbc:
	case cryptonight_aeon:
	case cryptonight_lite:
		return CRYPTONIGHT_LITE_MASK;
	case cryptonight_bittube2:
	case cryptonight_haven:
	case cryptonight_heavy:
		return CRYPTONIGHT_HEAVY_MASK;
	default:
		return 0;
	}
}

inline size_t cn_select_iter(algo_cn algo)
{
	switch(algo)
	{
	case cryptonight_stellite:
	case cryptonight_monero:
	case cryptonight_monero_v8:
	case cryptonight:
		return CRYPTONIGHT_ITER;
	case cryptonight_ipbc:
	case cryptonight_aeon:
	case cryptonight_lite:
		return CRYPTONIGHT_LITE_ITER;
	case cryptonight_bittube2:
	case cryptonight_haven:
	case cryptonight_heavy:
		return CRYPTONIGHT_HEAVY_ITER;
	case cryptonight_masari:
		return CRYPTONIGHT_MASARI_ITER;
	default:
		return 0;
	}
}

static algo_cn ALGO = 0;
static bool SOFT_AES = true;
static bool PREFETCH = true;
static size_t MEM;
static cryptonight_ctx _ALIGN(256) g_stCtx;


void do_blake_hash(const void* input, size_t len, char* output) {
    blake256_hash((uint8_t*)output, input, len);
}

void do_groestl_hash(const void* input, size_t len, char* output) {
#if defined(__AES__)
    hashState_groestl256 ctx;
    init_groestl256( &ctx, 32 );
    update_and_final_groestl256( &ctx, output, input, len * 8 );
#else
    groestl(input, len * 8, (uint8_t*)output);
#endif
}

void do_jh_hash(const void* input, size_t len, char* output) {
    jh_hash(32 * 8, input, 8 * len, (uint8_t*)output);
}

void do_skein_hash(const void* input, size_t len, char* output) {
    skein_hash(8 * 32, input, 8 * len, (uint8_t*)output);
}

void (* const extra_hashes[4])( const void *, size_t, char *) =
    { do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash };

// This will shift and xor tmp1 into itself as 4 32-bit vals such as
// sl_xor(a1 a2 a3 a4) = a1 (a2^a1) (a3^a2^a1) (a4^a3^a2^a1)
static inline __m128i sl_xor(__m128i tmp1)
{
	__m128i tmp4;
	tmp4 = _mm_slli_si128(tmp1, 0x04);
	tmp1 = _mm_xor_si128(tmp1, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	tmp1 = _mm_xor_si128(tmp1, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	tmp1 = _mm_xor_si128(tmp1, tmp4);
	return tmp1;
}


static inline void soft_aes_genkey_sub(__m128i* xout0, __m128i* xout2, uint8_t rcon)
{
	__m128i xout1 = soft_aeskeygenassist(*xout2, rcon);
	xout1 = _mm_shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
	*xout0 = sl_xor(*xout0);
	*xout0 = _mm_xor_si128(*xout0, xout1);
	xout1 = soft_aeskeygenassist(*xout0, 0x00);
	xout1 = _mm_shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
	*xout2 = sl_xor(*xout2);
	*xout2 = _mm_xor_si128(*xout2, xout1);
}

//template<bool SOFT_AES>
static inline void aes_genkey(const __m128i* memory, __m128i* k0, __m128i* k1, __m128i* k2, __m128i* k3,
	__m128i* k4, __m128i* k5, __m128i* k6, __m128i* k7, __m128i* k8, __m128i* k9)
{
	__m128i xout0, xout2;

	xout0 = _mm_load_si128(memory);
	xout2 = _mm_load_si128(memory+1);
	*k0 = xout0;
	*k1 = xout2;

	if(SOFT_AES)
		soft_aes_genkey_sub(&xout0, &xout2, 0x01);
	else
		;//aes_genkey_sub<0x01>(&xout0, &xout2);
	*k2 = xout0;
	*k3 = xout2;

	if(SOFT_AES)
		soft_aes_genkey_sub(&xout0, &xout2, 0x02);
	else
		;//aes_genkey_sub<0x02>(&xout0, &xout2);
	*k4 = xout0;
	*k5 = xout2;

	if(SOFT_AES)
		soft_aes_genkey_sub(&xout0, &xout2, 0x04);
	else
		;//aes_genkey_sub<0x04>(&xout0, &xout2);
	*k6 = xout0;
	*k7 = xout2;

	if(SOFT_AES)
		soft_aes_genkey_sub(&xout0, &xout2, 0x08);
	else
		;//aes_genkey_sub<0x08>(&xout0, &xout2);
	*k8 = xout0;
	*k9 = xout2;
}

static inline void aes_round(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
	*x0 = _mm_aesenc_si128(*x0, key);
	*x1 = _mm_aesenc_si128(*x1, key);
	*x2 = _mm_aesenc_si128(*x2, key);
	*x3 = _mm_aesenc_si128(*x3, key);
	*x4 = _mm_aesenc_si128(*x4, key);
	*x5 = _mm_aesenc_si128(*x5, key);
	*x6 = _mm_aesenc_si128(*x6, key);
	*x7 = _mm_aesenc_si128(*x7, key);
}

static inline void soft_aes_round(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
	*x0 = soft_aesenc(*x0, key);
	*x1 = soft_aesenc(*x1, key);
	*x2 = soft_aesenc(*x2, key);
	*x3 = soft_aesenc(*x3, key);
	*x4 = soft_aesenc(*x4, key);
	*x5 = soft_aesenc(*x5, key);
	*x6 = soft_aesenc(*x6, key);
	*x7 = soft_aesenc(*x7, key);
}

inline void mix_and_propagate(__m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
	__m128i tmp0 = *x0;
	*x0 = _mm_xor_si128(*x0, *x1);
	*x1 = _mm_xor_si128(*x1, *x2);
	*x2 = _mm_xor_si128(*x2, *x3);
	*x3 = _mm_xor_si128(*x3, *x4);
	*x4 = _mm_xor_si128(*x4, *x5);
	*x5 = _mm_xor_si128(*x5, *x6);
	*x6 = _mm_xor_si128(*x6, *x7);
	*x7 = _mm_xor_si128(*x7, tmp0);
}

//template<size_t MEM, bool SOFT_AES, bool PREFETCH, xmrstak_algo ALGO>
void cn_explode_scratchpad(const __m128i* input, __m128i* output)
{
	// This is more than we have registers, compiler will assign 2 keys on the stack
	__m128i xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7;
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

	aes_genkey(input, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

	xin0 = _mm_load_si128(input + 4);
	xin1 = _mm_load_si128(input + 5);
	xin2 = _mm_load_si128(input + 6);
	xin3 = _mm_load_si128(input + 7);
	xin4 = _mm_load_si128(input + 8);
	xin5 = _mm_load_si128(input + 9);
	xin6 = _mm_load_si128(input + 10);
	xin7 = _mm_load_si128(input + 11);

	if(ALGO == cryptonight_heavy || ALGO == cryptonight_haven || ALGO == cryptonight_bittube2)
	{
		for(size_t i=0; i < 16; i++)
		{
			if(SOFT_AES)
			{
				soft_aes_round(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
				soft_aes_round(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
				soft_aes_round(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
				soft_aes_round(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
				soft_aes_round(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
				soft_aes_round(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
				soft_aes_round(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
				soft_aes_round(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
				soft_aes_round(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
				soft_aes_round(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			}
			else
			{
				aes_round(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
				aes_round(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
				aes_round(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
				aes_round(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
				aes_round(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
				aes_round(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
				aes_round(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
				aes_round(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
				aes_round(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
				aes_round(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			}
			mix_and_propagate(&xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		}
	}

	for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
	{
		if(SOFT_AES)
		{
			soft_aes_round(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		}
		else
		{
			aes_round(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		}

		_mm_store_si128(output + i + 0, xin0);
		_mm_store_si128(output + i + 1, xin1);
		_mm_store_si128(output + i + 2, xin2);
		_mm_store_si128(output + i + 3, xin3);

		if(PREFETCH)
			_mm_prefetch((const char*)output + i + 0, _MM_HINT_T2);

		_mm_store_si128(output + i + 4, xin4);
		_mm_store_si128(output + i + 5, xin5);
		_mm_store_si128(output + i + 6, xin6);
		_mm_store_si128(output + i + 7, xin7);

		if(PREFETCH)
			_mm_prefetch((const char*)output + i + 4, _MM_HINT_T2);
	}
}

//template<size_t MEM, bool SOFT_AES, bool PREFETCH, xmrstak_algo ALGO>
void cn_implode_scratchpad(const __m128i* input, __m128i* output)
{
	// This is more than we have registers, compiler will assign 2 keys on the stack
	__m128i xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7;
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

	aes_genkey(output + 2, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

	xout0 = _mm_load_si128(output + 4);
	xout1 = _mm_load_si128(output + 5);
	xout2 = _mm_load_si128(output + 6);
	xout3 = _mm_load_si128(output + 7);
	xout4 = _mm_load_si128(output + 8);
	xout5 = _mm_load_si128(output + 9);
	xout6 = _mm_load_si128(output + 10);
	xout7 = _mm_load_si128(output + 11);

	for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
	{
		if(PREFETCH)
			_mm_prefetch((const char*)input + i + 0, _MM_HINT_NTA);

		xout0 = _mm_xor_si128(_mm_load_si128(input + i + 0), xout0);
		xout1 = _mm_xor_si128(_mm_load_si128(input + i + 1), xout1);
		xout2 = _mm_xor_si128(_mm_load_si128(input + i + 2), xout2);
		xout3 = _mm_xor_si128(_mm_load_si128(input + i + 3), xout3);

		if(PREFETCH)
			_mm_prefetch((const char*)input + i + 4, _MM_HINT_NTA);

		xout4 = _mm_xor_si128(_mm_load_si128(input + i + 4), xout4);
		xout5 = _mm_xor_si128(_mm_load_si128(input + i + 5), xout5);
		xout6 = _mm_xor_si128(_mm_load_si128(input + i + 6), xout6);
		xout7 = _mm_xor_si128(_mm_load_si128(input + i + 7), xout7);

		if(SOFT_AES)
		{
			soft_aes_round(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		}
		else
		{
			aes_round(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		}

		if(ALGO == cryptonight_heavy || ALGO == cryptonight_haven || ALGO == cryptonight_bittube2)
			mix_and_propagate(&xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
	}

	if(ALGO == cryptonight_heavy || ALGO == cryptonight_haven || ALGO == cryptonight_bittube2)
	{
		for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
		{
			if(PREFETCH)
				_mm_prefetch((const char*)input + i + 0, _MM_HINT_NTA);

			xout0 = _mm_xor_si128(_mm_load_si128(input + i + 0), xout0);
			xout1 = _mm_xor_si128(_mm_load_si128(input + i + 1), xout1);
			xout2 = _mm_xor_si128(_mm_load_si128(input + i + 2), xout2);
			xout3 = _mm_xor_si128(_mm_load_si128(input + i + 3), xout3);

			if(PREFETCH)
				_mm_prefetch((const char*)input + i + 4, _MM_HINT_NTA);

			xout4 = _mm_xor_si128(_mm_load_si128(input + i + 4), xout4);
			xout5 = _mm_xor_si128(_mm_load_si128(input + i + 5), xout5);
			xout6 = _mm_xor_si128(_mm_load_si128(input + i + 6), xout6);
			xout7 = _mm_xor_si128(_mm_load_si128(input + i + 7), xout7);

			if(SOFT_AES)
			{
				soft_aes_round(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				soft_aes_round(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				soft_aes_round(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				soft_aes_round(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				soft_aes_round(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				soft_aes_round(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				soft_aes_round(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				soft_aes_round(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				soft_aes_round(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				soft_aes_round(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			}
			else
			{
				aes_round(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				aes_round(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				aes_round(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				aes_round(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				aes_round(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				aes_round(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				aes_round(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				aes_round(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				aes_round(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				aes_round(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			}

			if(ALGO == cryptonight_heavy || ALGO == cryptonight_haven || ALGO == cryptonight_bittube2)
				mix_and_propagate(&xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		}

		for(size_t i=0; i < 16; i++)
		{
			if(SOFT_AES)
			{
				soft_aes_round(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				soft_aes_round(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				soft_aes_round(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				soft_aes_round(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				soft_aes_round(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				soft_aes_round(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				soft_aes_round(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				soft_aes_round(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				soft_aes_round(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				soft_aes_round(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			}
			else
			{
				aes_round(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				aes_round(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				aes_round(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				aes_round(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				aes_round(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				aes_round(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				aes_round(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				aes_round(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				aes_round(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
				aes_round(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			}

			mix_and_propagate(&xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		}
	}

	_mm_store_si128(output + 4, xout0);
	_mm_store_si128(output + 5, xout1);
	_mm_store_si128(output + 6, xout2);
	_mm_store_si128(output + 7, xout3);
	_mm_store_si128(output + 8, xout4);
	_mm_store_si128(output + 9, xout5);
	_mm_store_si128(output + 10, xout6);
	_mm_store_si128(output + 11, xout7);
}

inline uint64_t int_sqrt33_1_double_precision(const uint64_t n0)
{
	__m128d x = _mm_castsi128_pd(_mm_add_epi64(_mm_cvtsi64_si128(n0 >> 12), _mm_set_epi64x(0, 1023ULL << 52)));
	x = _mm_sqrt_sd(_mm_setzero_pd(), x);
	uint64_t r = (uint64_t)(_mm_cvtsi128_si64(_mm_castpd_si128(x)));

	const uint64_t s = r >> 20;
	r >>= 19;

	uint64_t x2 = (s - (1022ULL << 32)) * (r - s - (1022ULL << 32) + 1);

#ifdef __INTEL_COMPILER
	_addcarry_u64(_subborrow_u64(0, x2, n0, (unsigned __int64*)&x2), r, 0, (unsigned __int64*)&r);
#elif defined(_MSC_VER) || (__GNUC__ >= 7)
	_addcarry_u64(_subborrow_u64(0, x2, n0, (unsigned long long int*)&x2), r, 0, (unsigned long long int*)&r);
#else
	// GCC versions prior to 7 don't generate correct assembly for _subborrow_u64 -> _addcarry_u64 sequence
	// Fallback to simpler code
	if (x2 < n0) ++r;
#endif
	return r;
}

inline __m128i aes_round_bittube2(const __m128i* val, const __m128i* key)
{
	__attribute__((aligned(16))) uint32_t k[4];
	__attribute__((aligned(16))) uint32_t x[4];
	_mm_store_si128((__m128i*)k, *key);
	_mm_store_si128((__m128i*)x, _mm_xor_si128(*val, _mm_cmpeq_epi32(_mm_setzero_si128(), _mm_setzero_si128()))); // x = ~val
	#define BYTE(p, i) ((unsigned char*)&p)[i]
	k[0] ^= saes_table[0][BYTE(x[0], 0)] ^ saes_table[1][BYTE(x[1], 1)] ^ saes_table[2][BYTE(x[2], 2)] ^ saes_table[3][BYTE(x[3], 3)];
	x[0] ^= k[0];
	k[1] ^= saes_table[0][BYTE(x[1], 0)] ^ saes_table[1][BYTE(x[2], 1)] ^ saes_table[2][BYTE(x[3], 2)] ^ saes_table[3][BYTE(x[0], 3)];
	x[1] ^= k[1];
	k[2] ^= saes_table[0][BYTE(x[2], 0)] ^ saes_table[1][BYTE(x[3], 1)] ^ saes_table[2][BYTE(x[0], 2)] ^ saes_table[3][BYTE(x[1], 3)];
	x[2] ^= k[2];
	k[3] ^= saes_table[0][BYTE(x[3], 0)] ^ saes_table[1][BYTE(x[0], 1)] ^ saes_table[2][BYTE(x[1], 2)] ^ saes_table[3][BYTE(x[2], 3)];
	#undef BYTE
	return _mm_load_si128((__m128i*)k);
}

//template<xmrstak_algo ALGO>
inline void cryptonight_monero_tweak(uint64_t* mem_out, __m128i tmp)
{
	mem_out[0] = _mm_cvtsi128_si64(tmp);

	tmp = _mm_castps_si128(_mm_movehl_ps(_mm_castsi128_ps(tmp), _mm_castsi128_ps(tmp)));
	uint64_t vh = _mm_cvtsi128_si64(tmp);

	uint8_t x = (uint8_t)(vh >> 24);
	static const uint16_t table = 0x7531;
	if(ALGO == cryptonight_monero || ALGO == cryptonight_aeon || ALGO == cryptonight_ipbc || ALGO == cryptonight_masari || ALGO == cryptonight_bittube2)
	{
		const uint8_t index = (((x >> 3) & 6) | (x & 1)) << 1;
		vh ^= ((table >> index) & 0x3) << 28;

		mem_out[1] = vh;
	}
	else if(ALGO == cryptonight_stellite)
	{
		const uint8_t index = (((x >> 4) & 6) | (x & 1)) << 1;
		vh ^= ((table >> index) & 0x3) << 28;

		mem_out[1] = vh;
	}

}

//typedef __m128i GetOptimalSqrtType_t;
typedef uint64_t GetOptimalSqrtType_t;


	inline void assign64to128(__m128i* output, const uint64_t input)
	{
		*output = _mm_cvtsi64_si128(input);
	}

	inline void assign(uint64_t* output, const uint64_t input)
	{
		*output = input;
	}

	inline void assign128to64(uint64_t* output, const __m128i* input)
	{
		*output = _mm_cvtsi128_si64(*input);
	}
	/** @} */

	inline void set_float_rounding_mode()
	{
#ifdef _MSC_VER
		_control87(RC_DOWN, MCW_RC);
#else
		fesetround(FE_DOWNWARD);
#endif
	}


#define CN_MONERO_V8_SHUFFLE_0(n, l0, idx0, ax0, bx0, bx1) \
	/* Shuffle the other 3x16 byte chunks in the current 64-byte cache line */ \
	if(ALGO == cryptonight_monero_v8) \
	{ \
		const uint64_t idx1 = idx0 & MASK; \
		const __m128i chunk1 = _mm_load_si128((__m128i *)&l0[idx1 ^ 0x10]); \
		const __m128i chunk2 = _mm_load_si128((__m128i *)&l0[idx1 ^ 0x20]); \
		const __m128i chunk3 = _mm_load_si128((__m128i *)&l0[idx1 ^ 0x30]); \
		_mm_store_si128((__m128i *)&l0[idx1 ^ 0x10], _mm_add_epi64(chunk3, bx1)); \
		_mm_store_si128((__m128i *)&l0[idx1 ^ 0x20], _mm_add_epi64(chunk1, bx0)); \
		_mm_store_si128((__m128i *)&l0[idx1 ^ 0x30], _mm_add_epi64(chunk2, ax0)); \
	}

#define CN_MONERO_V8_SHUFFLE_1(n, l0, idx0, ax0, bx0, bx1, lo, hi) \
	/* Shuffle the other 3x16 byte chunks in the current 64-byte cache line */ \
	if(ALGO == cryptonight_monero_v8) \
	{ \
		const uint64_t idx1 = idx0 & MASK; \
		const __m128i chunk1 = _mm_xor_si128(_mm_load_si128((__m128i *)&l0[idx1 ^ 0x10]), _mm_set_epi64x(lo, hi)); \
		const __m128i chunk2 = _mm_load_si128((__m128i *)&l0[idx1 ^ 0x20]); \
		hi ^= ((uint64_t*)&chunk2)[0]; \
		lo ^= ((uint64_t*)&chunk2)[1]; \
		const __m128i chunk3 = _mm_load_si128((__m128i *)&l0[idx1 ^ 0x30]); \
		_mm_store_si128((__m128i *)&l0[idx1 ^ 0x10], _mm_add_epi64(chunk3, bx1)); \
		_mm_store_si128((__m128i *)&l0[idx1 ^ 0x20], _mm_add_epi64(chunk1, bx0)); \
		_mm_store_si128((__m128i *)&l0[idx1 ^ 0x30], _mm_add_epi64(chunk2, ax0)); \
	}

#define CN_MONERO_V8_DIV(n, cx, sqrt_result, division_result_xmm, cl) \
	if(ALGO == cryptonight_monero_v8) \
	{ \
		uint64_t sqrt_result_tmp; \
		assign(&sqrt_result_tmp, sqrt_result); \
		/* Use division and square root results from the _previous_ iteration to hide the latency */ \
		const uint64_t cx_64 = _mm_cvtsi128_si64(cx); \
		cl ^= (uint64_t)(_mm_cvtsi128_si64(division_result_xmm)) ^ (sqrt_result_tmp << 32); \
		const uint32_t d = (cx_64 + (sqrt_result_tmp << 1)) | 0x80000001UL; \
		/* Most and least significant bits in the divisor are set to 1 \
		 * to make sure we don't divide by a small or even number, \
		 * so there are no shortcuts for such cases \
		 * \
		 * Quotient may be as large as (2^64 - 1)/(2^31 + 1) = 8589934588 = 2^33 - 4 \
		 * We drop the highest bit to fit both quotient and remainder in 32 bits \
		 */  \
		/* Compiler will optimize it to a single div instruction */ \
		const uint64_t cx_s = _mm_cvtsi128_si64(_mm_srli_si128(cx, 8)); \
		const uint64_t division_result = (uint32_t)(cx_s / d) + ((cx_s % d) << 32); \
		division_result_xmm = _mm_cvtsi64_si128((int64_t)(division_result)); \
		/* Use division_result as an input for the square root to prevent parallel implementation in hardware */ \
		assign(&sqrt_result, int_sqrt33_1_double_precision(cx_64 + division_result)); \
	}

#define CN_INIT_SINGLE \
	if((ALGO == cryptonight_monero || ALGO == cryptonight_aeon || ALGO == cryptonight_ipbc || ALGO == cryptonight_stellite || ALGO == cryptonight_masari || ALGO == cryptonight_bittube2) && len < 43) \
	{ \
		memset(output, 0, 32 * N); \
		return; \
	}

#define CN_INIT(n, monero_const, l0, ax0, bx0, idx0, ptr0, bx1, sqrt_result, division_result_xmm) \
	keccak((const uint8_t *)input + len * n, len, ctx->hash_state, 200); \
	uint64_t monero_const; \
	if(ALGO == cryptonight_monero || ALGO == cryptonight_aeon || ALGO == cryptonight_ipbc || ALGO == cryptonight_stellite || ALGO == cryptonight_masari || ALGO == cryptonight_bittube2) \
	{ \
		/* monero_const =  *reinterpret_cast<const uint64_t*>(reinterpret_cast<const uint8_t*>(input) + len * n + 35); */\
		/* monero_const ^=  *(reinterpret_cast<const uint64_t*>(ctx[n]->hash_state) + 24); */ \
		monero_const = *((const uint64_t*) (((const uint8_t*)input) + 35)) ^ *((const uint64_t*)(ctx->hash_state + 24)); \
	} \
	/* Optim - 99% time boundary */ \
	cn_explode_scratchpad((__m128i*)ctx->hash_state, (__m128i*)ctx->long_state); \
	\
	__m128i ax0; \
	uint64_t idx0; \
	__m128i bx0; \
	uint8_t* l0 = ctx->long_state; \
	/* BEGIN cryptonight_monero_v8 variables */ \
	__m128i bx1; \
	__m128i division_result_xmm; \
	GetOptimalSqrtType_t sqrt_result; \
	/* END cryptonight_monero_v8 variables */ \
	{ \
		uint64_t* h0 = (uint64_t*)ctx->hash_state; \
		idx0 = h0[0] ^ h0[4]; \
		ax0 = _mm_set_epi64x(h0[1] ^ h0[5], idx0); \
		bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]); \
		if(ALGO == cryptonight_monero_v8) \
		{ \
			bx1 = _mm_set_epi64x(h0[9] ^ h0[11], h0[8] ^ h0[10]); \
			division_result_xmm = _mm_cvtsi64_si128(h0[12]); \
			assign(&sqrt_result, h0[13]); \
			set_float_rounding_mode(); \
		} \
	} \
	__m128i *ptr0

#define CN_STEP1(n, monero_const, l0, ax0, bx0, idx0, ptr0, cx, bx1) \
	__m128i cx; \
	ptr0 = (__m128i *)&l0[idx0 & MASK]; \
	cx = _mm_load_si128(ptr0); \
	if (ALGO == cryptonight_bittube2) \
	{ \
		cx = aes_round_bittube2(&cx, &ax0); \
	} \
	else \
	{ \
		if(SOFT_AES) \
			cx = soft_aesenc(cx, ax0); \
		else \
			cx = _mm_aesenc_si128(cx, ax0); \
	} \
	CN_MONERO_V8_SHUFFLE_0(n, l0, idx0, ax0, bx0, bx1)

#define CN_STEP2(n, monero_const, l0, ax0, bx0, idx0, ptr0, cx) \
	if(ALGO == cryptonight_monero || ALGO == cryptonight_aeon || ALGO == cryptonight_ipbc || ALGO == cryptonight_stellite || ALGO == cryptonight_masari || ALGO == cryptonight_bittube2) \
		cryptonight_monero_tweak((uint64_t*)ptr0, _mm_xor_si128(bx0, cx)); \
	else \
		_mm_store_si128((__m128i *)ptr0, _mm_xor_si128(bx0, cx)); \
	idx0 = _mm_cvtsi128_si64(cx); \
	\
	ptr0 = (__m128i *)&l0[idx0 & MASK]; \
	if(PREFETCH) \
		_mm_prefetch((const char*)ptr0, _MM_HINT_T0); \
	if(ALGO != cryptonight_monero_v8) \
		bx0 = cx

#define CN_STEP3(n, monero_const, l0, ax0, bx0, idx0, ptr0, lo, cl, ch, al0, ah0, cx, bx1, sqrt_result, division_result_xmm) \
	uint64_t lo, cl, ch; \
	uint64_t al0 = _mm_cvtsi128_si64(ax0); \
	uint64_t ah0 = ((uint64_t*)&ax0)[1]; \
	cl = ((uint64_t*)ptr0)[0]; \
	ch = ((uint64_t*)ptr0)[1]; \
	CN_MONERO_V8_DIV(n, cx, sqrt_result, division_result_xmm, cl); \
	{ \
		uint64_t hi; \
		lo = _umul128(idx0, cl, &hi); \
		CN_MONERO_V8_SHUFFLE_1(n, l0, idx0, ax0, bx0, bx1, lo, hi); \
		ah0 += lo; \
		al0 += hi; \
	} \
	if(ALGO == cryptonight_monero_v8) \
	{ \
		bx1 = bx0; \
		bx0 = cx; \
	} \
	((uint64_t*)ptr0)[0] = al0; \
	if(PREFETCH) \
		_mm_prefetch((const char*)ptr0, _MM_HINT_T0)

#define CN_STEP4(n, monero_const, l0, ax0, bx0, idx0, ptr0, lo, cl, ch, al0, ah0) \
	if (ALGO == cryptonight_monero || ALGO == cryptonight_aeon || ALGO == cryptonight_ipbc || ALGO == cryptonight_stellite || ALGO == cryptonight_masari || ALGO == cryptonight_bittube2) \
	{ \
		if (ALGO == cryptonight_ipbc || ALGO == cryptonight_bittube2) \
			((uint64_t*)ptr0)[1] = ah0 ^ monero_const ^ ((uint64_t*)ptr0)[0]; \
		else \
			((uint64_t*)ptr0)[1] = ah0 ^ monero_const; \
	} \
	else \
		((uint64_t*)ptr0)[1] = ah0; \
	al0 ^= cl; \
	ah0 ^= ch; \
	ax0 = _mm_set_epi64x(ah0, al0); \
	idx0 = al0;

#define CN_STEP5(n, monero_const, l0, ax0, bx0, idx0, ptr0) \
	if(ALGO == cryptonight_heavy || ALGO == cryptonight_bittube2) \
	{ \
		ptr0 = (__m128i *)&l0[idx0 & MASK]; \
		int64_t u  = ((int64_t*)ptr0)[0]; \
		int32_t d  = ((int32_t*)ptr0)[2]; \
		int64_t q = u / (d | 0x5); \
		\
		((int64_t*)ptr0)[0] = u ^ q; \
		idx0 = d ^ q; \
	} \
	else if(ALGO == cryptonight_haven) \
	{ \
		ptr0 = (__m128i *)&l0[idx0 & MASK]; \
		int64_t u  = ((int64_t*)ptr0)[0]; \
		int32_t d  = ((int32_t*)ptr0)[2]; \
		int64_t q = u / (d | 0x5); \
		\
		((int64_t*)ptr0)[0] = u ^ q; \
		idx0 = (~d) ^ q; \
	}

#define CN_FINALIZE(n) \
	/* Optim - 90% time boundary */ \
	cn_implode_scratchpad((__m128i*)ctx->long_state, (__m128i*)ctx->hash_state); \
	/* Optim - 99% time boundary */ \
	keccakf((uint64_t*)ctx->hash_state, 24); \
	extra_hashes[ctx->hash_state[0] & 3](ctx->hash_state, 200, (char*)output + 32 * n)

#ifndef _MSC_VER
#	define CN_DEFER(...) __VA_ARGS__
#else
#	define CN_EMPTY(...)
#	define CN_DEFER(...) __VA_ARGS__ CN_EMPTY()
#endif

#define CN_ENUM_0(n, ...) n
#define CN_ENUM_1(n, x1) n, x1 ## n
#define CN_ENUM_2(n, x1, x2) n, x1 ## n, x2 ## n
#define CN_ENUM_3(n, x1, x2, x3) n, x1 ## n, x2 ## n, x3 ## n
#define CN_ENUM_4(n, x1, x2, x3, x4) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n
#define CN_ENUM_5(n, x1, x2, x3, x4, x5) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n, x5 ## n
#define CN_ENUM_6(n, x1, x2, x3, x4, x5, x6) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n, x5 ## n, x6 ## n
#define CN_ENUM_7(n, x1, x2, x3, x4, x5, x6, x7) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n, x5 ## n, x6 ## n, x7 ## n
#define CN_ENUM_8(n, x1, x2, x3, x4, x5, x6, x7, x8) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n, x5 ## n, x6 ## n, x7 ## n, x8 ## n
#define CN_ENUM_9(n, x1, x2, x3, x4, x5, x6, x7, x8, x9) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n, x5 ## n, x6 ## n, x7 ## n, x8 ## n, x9 ## n
#define CN_ENUM_10(n, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n, x5 ## n, x6 ## n, x7 ## n, x8 ## n, x9 ## n, x10 ## n
#define CN_ENUM_11(n, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n, x5 ## n, x6 ## n, x7 ## n, x8 ## n, x9 ## n, x10 ## n, x11 ## n
#define CN_ENUM_12(n, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n, x5 ## n, x6 ## n, x7 ## n, x8 ## n, x9 ## n, x10 ## n, x11 ## n, x12 ## n
#define CN_ENUM_13(n, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n, x5 ## n, x6 ## n, x7 ## n, x8 ## n, x9 ## n, x10 ## n, x11 ## n, x12 ## n, x13 ## n
#define CN_ENUM_14(n, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n, x5 ## n, x6 ## n, x7 ## n, x8 ## n, x9 ## n, x10 ## n, x11 ## n, x12 ## n, x13 ## n, x14 ## n
#define CN_ENUM_15(n, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15) n, x1 ## n, x2 ## n, x3 ## n, x4 ## n, x5 ## n, x6 ## n, x7 ## n, x8 ## n, x9 ## n, x10 ## n, x11 ## n, x12 ## n, x13 ## n, x14 ## n, x15 ## n


#define CN_EXEC(f,...) CN_DEFER(f)(__VA_ARGS__)
#define REPEAT_1(n, f, ...) CN_EXEC(f, CN_ENUM_ ## n(0, __VA_ARGS__))

static inline void print8u(const char *str, uint8_t *v, uint32_t len) {

  printf("%s:", str);
  for(uint32_t i = 0; i < len; i++) {

    if ((i % 8) == 0) printf("\n");
    printf("0x%02x, ", v[i]);
  }
  printf("\n\n");
}

static uint8_t in[76] = {
	0x09, 0x09, 0xe7, 0xe8, 0xbb, 0xde, 0x05, 0x5f, 
	0xf8, 0x1d, 0x4f, 0xa3, 0x8a, 0xaf, 0xb5, 0x8a, 
	0xf0, 0x7f, 0x4f, 0x6c, 0xb6, 0xd8, 0xdc, 0xf7, 
	0x6a, 0xd7, 0x52, 0x8d, 0xce, 0xfc, 0x9a, 0xe8, 
	0x26, 0x17, 0x20, 0x64, 0x1a, 0xf1, 0x26, 0x00, 
	0x00, 0x00, 0x00, 0xef, 0x26, 0x76, 0xe2, 0xaf, 
	0xa6, 0x59, 0xbe, 0xe5, 0xbc, 0x79, 0x65, 0x91, 
	0x34, 0x96, 0x91, 0x64, 0x07, 0xcf, 0x76, 0xea, 
	0x16, 0xba, 0xbe, 0x2b, 0x41, 0xff, 0x54, 0x37, 
	0x4b, 0x14, 0xdc, 0x17, 

};

static uint8_t ou[32] = {
	0x57, 0xbc, 0x54, 0x51, 0x96, 0x93, 0x8b, 0x26, 
	0x35, 0x0b, 0x11, 0x39, 0x52, 0x43, 0x70, 0x96, 
	0xaa, 0x3e, 0x49, 0x9a, 0xe8, 0x77, 0x8d, 0xf5, 
	0x58, 0x60, 0xb1, 0x37, 0x80, 0xd8, 0xc0, 0x20, 
};

void cryptonight_hash( void *restrict output, const void *input, int len )
{
	size_t MASK = cn_select_mask(ALGO);
	size_t ITERATIONS = cn_select_iter(ALGO);
	MEM = cn_select_memory(ALGO);
	uint32_t N = 1;
	cryptonight_ctx* ctx = malloc(sizeof(cryptonight_ctx));

	CN_INIT_SINGLE;
	REPEAT_1(9, CN_INIT, monero_const, l0, ax0, bx0, idx0, ptr0, bx1, sqrt_result, division_result_xmm);

	// Optim - 90% time boundary
	for(size_t i = 0; i < ITERATIONS; i++)
	{
		REPEAT_1(8, CN_STEP1, monero_const, l0, ax0, bx0, idx0, ptr0, cx, bx1);
		REPEAT_1(7, CN_STEP2, monero_const, l0, ax0, bx0, idx0, ptr0, cx);
		REPEAT_1(15, CN_STEP3, monero_const, l0, ax0, bx0, idx0, ptr0, lo, cl, ch, al0, ah0, cx, bx1, sqrt_result, division_result_xmm);
		REPEAT_1(11, CN_STEP4, monero_const, l0, ax0, bx0, idx0, ptr0, lo, cl, ch, al0, ah0);
		REPEAT_1(6, CN_STEP5, monero_const, l0, ax0, bx0, idx0, ptr0);
	}

	REPEAT_1(0, CN_FINALIZE);
	free(ctx);
}

void cryptonight_hash_suw( void *restrict output, const void *input )
{
  cryptonight_hash( output, input, 76 );
}

int scanhash_cryptonight( int thr_id, struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done )
 {
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;

    uint32_t *nonceptr = (uint32_t*) (((char*)pdata) + 39);
    uint32_t n = *nonceptr - 1;
    const uint32_t first_nonce = n + 1;
    const uint32_t Htarg = ptarget[7];
    uint32_t hash[32 / 4] __attribute__((aligned(32)));


    do
    {
       *nonceptr = ++n;
       cryptonight_hash( hash, pdata, 76 );
       if (unlikely( hash[7] < Htarg ))
       {
           *hashes_done = n - first_nonce + 1;
	   return true;
       }
    } while (likely((n <= max_nonce && !work_restart[thr_id].restart)));

    *hashes_done = n - first_nonce + 1;
    return 0;
}

bool register_cryptonight_algo( algo_gate_t* gate )
{
	ALGO = cryptonight;
  register_json_rpc2( gate );
  gate->optimizations = SSE2_OPT | AES_OPT;
  gate->scanhash         = (void*)&scanhash_cryptonight;
  gate->hash             = (void*)&cryptonight_hash;
  gate->hash_suw         = (void*)&cryptonight_hash_suw;
  gate->get_max64        = (void*)&get_max64_0x40LL;
  return true;
};

bool register_cryptonightv7_algo( algo_gate_t* gate )
{
	ALGO = cryptonight_monero;
  register_json_rpc2( gate );
  gate->optimizations = SSE2_OPT | AES_OPT;
  gate->scanhash      = (void*)&scanhash_cryptonight;
  gate->hash          = (void*)&cryptonight_hash;
  gate->hash_suw      = (void*)&cryptonight_hash_suw;
  gate->get_max64     = (void*)&get_max64_0x40LL;
  return true;
};

bool register_cryptonightv8_algo( algo_gate_t* gate )
{
	ALGO = cryptonight_monero_v8;
  register_json_rpc2( gate );
  gate->optimizations = SSE2_OPT | AES_OPT;
  gate->scanhash      = (void*)&scanhash_cryptonight;
  gate->hash          = (void*)&cryptonight_hash;
  gate->hash_suw      = (void*)&cryptonight_hash_suw;
  gate->get_max64     = (void*)&get_max64_0x40LL;
  return true;
};

bool register_cryptonightheavy_algo( algo_gate_t* gate )
{
	ALGO = cryptonight_heavy;
  register_json_rpc2( gate );
  gate->optimizations = SSE2_OPT | AES_OPT;
  gate->scanhash      = (void*)&scanhash_cryptonight;
  gate->hash          = (void*)&cryptonight_hash;
  gate->hash_suw      = (void*)&cryptonight_hash_suw;
  gate->get_max64     = (void*)&get_max64_0x40LL;
  return true;
};


