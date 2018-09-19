#include "lyra2rev2-gate.h"
#include <memory.h>
#include "algo/blake/sph_blake.h"
#include "algo/cubehash/sph_cubehash.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/cubehash/sse2/cubehash_sse2.h" 
#include "drv_api.h"

typedef struct {
        cubehashParam           cube1;
        cubehashParam           cube2;
        sph_blake256_context     blake;
        sph_keccak256_context    keccak;
        sph_skein256_context     skein;
        sph_bmw256_context       bmw;

} lyra2v2_ctx_holder;

static lyra2v2_ctx_holder lyra2v2_ctx;
static __thread sph_blake256_context l2v2_blake_mid;

bool init_lyra2rev2_ctx()
{
        cubehashInit( &lyra2v2_ctx.cube1, 256, 16, 32 );
        cubehashInit( &lyra2v2_ctx.cube2, 256, 16, 32 );
        sph_blake256_init( &lyra2v2_ctx.blake );
        sph_keccak256_init( &lyra2v2_ctx.keccak );
        sph_skein256_init( &lyra2v2_ctx.skein );
        sph_bmw256_init( &lyra2v2_ctx.bmw );
        return true;
}

void l2v2_blake256_midstate( const void* input )
{
    memcpy( &l2v2_blake_mid, &lyra2v2_ctx.blake, sizeof l2v2_blake_mid );
    sph_blake256( &l2v2_blake_mid, input, 64 );
}

void lyra2rev2_hash( void *state, const void *input )
{
        lyra2v2_ctx_holder ctx __attribute__ ((aligned (64))); 
        memcpy( &ctx, &lyra2v2_ctx, sizeof(lyra2v2_ctx) );
        uint8_t hash[128] __attribute__ ((aligned (64)));
        #define hashA hash
        #define hashB hash+64
        const int midlen = 64;            // bytes
        const int tail   = 80 - midlen;   // 16

        memcpy( &ctx.blake, &l2v2_blake_mid, sizeof l2v2_blake_mid );
	sph_blake256( &ctx.blake, (uint8_t*)input + midlen, tail );
	sph_blake256_close( &ctx.blake, hashA );

	sph_keccak256( &ctx.keccak, hashA, 32 );
	sph_keccak256_close(&ctx.keccak, hashB);

        cubehashUpdateDigest( &ctx.cube1, (byte*) hashA,
                              (const byte*) hashB, 32 );

	LYRA2REV2( l2v2_wholeMatrix, hashA, 32, hashA, 32, hashA, 32, 1, 4, 4 );

	sph_skein256( &ctx.skein, hashA, 32 );
	sph_skein256_close( &ctx.skein, hashB );

        cubehashUpdateDigest( &ctx.cube2, (byte*) hashA, 
                              (const byte*) hashB, 32 );

	sph_bmw256( &ctx.bmw, hashA, 32 );
	sph_bmw256_close( &ctx.bmw, hashB );

	memcpy( state, hashB, 32 );
}

static uint8_t g_msgIdx = 0;

static int _get_leadingZeroCnt(uint8_t *result) {

  int count = 0;

  for (int i = 0; i < 32; i++) {
    if (result[i] < 1)        {count += 8;}
    else if (result[i] < 2)   {count += 7; break;}
    else if (result[i] < 4)   {count += 6; break;}
    else if (result[i] < 8)   {count += 5; break;}
    else if (result[i] < 16)  {count += 4; break;}
    else if (result[i] < 32)  {count += 3; break;}
    else if (result[i] < 64)  {count += 2; break;}
    else if (result[i] < 128) {count += 1; break;}
    else break;
  }

  return count;
}


int scanhash_lyra2rev2(int thr_id, struct work *work,
	uint32_t max_nonce, uint64_t *hashes_done)
{
  uint32_t *pdata = work->data;
  uint32_t *ptarget = work->target;
  uint32_t endiandata[20] __attribute__ ((aligned (64)));
  uint32_t hash[8] __attribute__((aligned(64)));
  const uint32_t first_nonce = pdata[19];
  uint32_t nonce = first_nonce;
  const uint32_t Htarg = ptarget[7];
  uint8_t msgidx;
  int ncnt;

  if (opt_benchmark)
    ((uint32_t*)ptarget)[7] = 0x0000ff;

  swab32_array( endiandata, pdata, 20 );
  l2v2_blake256_midstate( endiandata );

  be32enc(&endiandata[19], nonce);
  uint8_t diff = _get_leadingZeroCnt((uint8_t *)ptarget);
  drv_send_work(g_msgIdx, diff, (uint8_t *)&nonce, 4, (uint8_t *)&endiandata[0], 80);
  do {
    ncnt = drv_get_nonce(&msgidx, (uint8_t *)&work->nonces[0]);
  } while((msgidx != g_msgIdx) || (ncnt == 0));

  for (int i = 0; i < ncnt; i++) {
    be32enc(&endiandata[19], work->nonces[i]);
    lyra2rev2_hash(hash, endiandata);

    if (hash[7] <= Htarg ) {
      if( !fulltest(hash, ptarget) ) {
        applog(LOG_ERR, "the diff of the nonce 0x%08x is not right",work->nonces[i]);
        return 1;
      }
    }
  }

  g_msgIdx += 1;
  return ncnt;
#if 0
  do {
    be32enc(&endiandata[19], nonce);
    lyra2rev2_hash(hash, endiandata);

    if (hash[7] <= Htarg )
    {
      if( fulltest(hash, ptarget) )
      {
        pdata[19] = nonce;
        work_set_target_ratio( work, hash );
        *hashes_done = pdata[19] - first_nonce;
        return 1;
      }
    }
    nonce++;

  } while (nonce < max_nonce && !work_restart[thr_id].restart);

  pdata[19] = nonce;
  *hashes_done = pdata[19] - first_nonce + 1;
  return 0;
  #endif
}

