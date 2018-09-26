#include "lyra2rev2-gate.h"
#include <memory.h>
#include "drv_api.h"
#if defined (__AVX2__)

#include "algo/blake/blake-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/cubehash/sse2/cubehash_sse2.h"

typedef struct {
   blake256_4way_context     blake;
   keccak256_4way_context    keccak;
   cubehashParam             cube;
   skein256_4way_context     skein;
   bmw256_4way_context          bmw;
} lyra2v2_4way_ctx_holder;

static lyra2v2_4way_ctx_holder l2v2_4way_ctx;

bool init_lyra2rev2_4way_ctx()
{
   keccak256_4way_init( &l2v2_4way_ctx.keccak );
   cubehashInit( &l2v2_4way_ctx.cube, 256, 16, 32 );
   skein256_4way_init( &l2v2_4way_ctx.skein );
   bmw256_4way_init( &l2v2_4way_ctx.bmw );
   return true;
}

void lyra2rev2_4way_hash( void *state, const void *input )
{
   uint32_t hash0[8] __attribute__ ((aligned (64)));
   uint32_t hash1[8] __attribute__ ((aligned (32)));
   uint32_t hash2[8] __attribute__ ((aligned (32)));
   uint32_t hash3[8] __attribute__ ((aligned (32)));
   uint32_t vhash[8*4] __attribute__ ((aligned (64)));
   uint64_t vhash64[4*4] __attribute__ ((aligned (64)));
   lyra2v2_4way_ctx_holder ctx __attribute__ ((aligned (64)));
   memcpy( &ctx, &l2v2_4way_ctx, sizeof(l2v2_4way_ctx) );

   blake256_4way( &ctx.blake, input + (64<<2), 16 );
   blake256_4way_close( &ctx.blake, vhash );

   mm256_reinterleave_4x64( vhash64, vhash, 256 );
   keccak256_4way( &ctx.keccak, vhash64, 32 );
   keccak256_4way_close( &ctx.keccak, vhash64 );
   mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, vhash64, 256 );

   cubehashUpdateDigest( &ctx.cube, (byte*) hash0, (const byte*) hash0, 32 );
   cubehashReinit( &ctx.cube );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash1, (const byte*) hash1, 32 );
   cubehashReinit( &ctx.cube );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash2, (const byte*) hash2, 32 );
   cubehashReinit( &ctx.cube );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash3, (const byte*) hash3, 32 );

   LYRA2REV2( l2v2_wholeMatrix, hash0, 32, hash0, 32, hash0, 32, 1, 4, 4 );
   LYRA2REV2( l2v2_wholeMatrix, hash1, 32, hash1, 32, hash1, 32, 1, 4, 4 );
   LYRA2REV2( l2v2_wholeMatrix, hash2, 32, hash2, 32, hash2, 32, 1, 4, 4 );
   LYRA2REV2( l2v2_wholeMatrix, hash3, 32, hash3, 32, hash3, 32, 1, 4, 4 );

   mm256_interleave_4x64( vhash64, hash0, hash1, hash2, hash3, 256 );
   skein256_4way( &ctx.skein, vhash64, 32 );
   skein256_4way_close( &ctx.skein, vhash64 );
   mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, vhash64, 256 );

   cubehashReinit( &ctx.cube );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash0, (const byte*) hash0, 32 );
   cubehashReinit( &ctx.cube );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash1, (const byte*) hash1, 32 );
   cubehashReinit( &ctx.cube );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash2, (const byte*) hash2, 32 );
   cubehashReinit( &ctx.cube );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash3, (const byte*) hash3, 32 );

   mm_interleave_4x32( vhash, hash0, hash1, hash2, hash3, 256 );
   bmw256_4way( &ctx.bmw, vhash, 32 );
   bmw256_4way_close( &ctx.bmw, vhash );

   mm_deinterleave_4x32( state, state+32, state+64, state+96, vhash, 256 );
}

static void print8u( const uint8_t *str, uint8_t *v, uint32_t len) {

  printf( "%s:", str);
  for( uint32_t i=0; i<len; i++) {

    if( ( i%16) == 0) printf( "\n");
    printf( "%02x ", v[ i]);
  }
  printf( "\n\n");
}

static void printv( const uint8_t *str, uint32_t *v, uint32_t len) {

  printf( "%s:", str);
  for( uint32_t i=0; i<len; i++) {

    if( ( i%8) == 0) printf( "\n");
    printf( "%08x ", v[ i]);
  }
  printf( "\n\n");
}

#define __FECTH_DATA 0

#if 1
static uint8_t g_msgIdx = 0;

static int _get_leadingZeroCnt(uint8_t *result) {

  int count = 0;

  for (int i = 31; i >= 0; i--) {
    //printf("0x%02x ", result[i]);
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

#if __FECTH_DATA
static uint8_t w[80] = {
  0x20, 0x00, 0x00, 0x00, 0x21, 0xaa, 0x4e, 0xae, 0x2a, 0xb7, 0x71, 0x6c, 0xaf, 0xaf, 0x2a, 0x28,
  0x35, 0xaa, 0x11, 0x34, 0x8d, 0x0f, 0x8d, 0xee, 0xc9, 0xb0, 0x70, 0x02, 0x46, 0x40, 0x09, 0xdb,
  0x9b, 0xea, 0x33, 0x50, 0x4c, 0x4e, 0x96, 0x52, 0x93, 0xea, 0xfc, 0x7b, 0x40, 0x7e, 0x41, 0x62,
  0xa3, 0xf4, 0x9f, 0x25, 0x87, 0x92, 0x17, 0x86, 0xaf, 0xec, 0x82, 0x01, 0x31, 0x7e, 0x6b, 0x51,
  0x90, 0x25, 0x28, 0x76, 0x5b, 0xa7, 0x7a, 0x75, 0x1b, 0x01, 0x9a, 0x55, 0x00, 0x00, 0x00, 0x00,
};
#endif
static uint32_t g_u32Ncnt = 0, g_u32MaxDiff = 0;
static uint32_t g_u32Work[20];
int scanhash_lyra2rev2_4way( int thr_id, struct work *work, uint32_t max_nonce,
                             uint64_t *hashes_done )
{
  uint32_t *pdata = work->data;
  uint32_t *ptarget = work->target;
  uint32_t endiandata[4*20] __attribute__ ((aligned (64)));
  uint32_t hash[4*8] __attribute__((aligned(64)));
  const uint32_t first_nonce = (pdata[19] + 15) & 0xfffffff0;
  uint32_t nonce = (first_nonce + 15) & 0xfffffff0;
  uint8_t msgidx;
  int ncnt;

  //printf("%s, %d: 0x%08x, 0x%08x, 0x%08x,0x%08x\n", __FUNCTION__, __LINE__, ptarget[7], ptarget[6], ptarget[5], ptarget[4]);
  if (opt_benchmark)
    ((uint32_t*)ptarget)[7] = 0x0000ff;

  uint8_t diff = _get_leadingZeroCnt((uint8_t *)ptarget);
  uint8_t diff1 = diff > 10 ? 18 : diff;
  #if __FECTH_DATA
  if (memcmp((uint8_t *)&w[0], g_u32Work, 76) != 0) {

    memcpy(pdata, w, 80);
    nonce = 0x0;
  #else
  if (memcmp((uint8_t *)&pdata[0], g_u32Work, 76) != 0) {
  #endif
    memcpy(g_u32Work, (uint8_t *)&pdata[0], 76);
    g_u32Work[19] = nonce;
    printf("new work,%d\n", g_msgIdx);

    drv_send_work(g_msgIdx, diff1, (uint8_t *)&nonce, 4, (uint8_t *)g_u32Work, 80);
    //print8u("work", g_u32Work, 80);
  }

  //printf("work: diff-%d %d, nonce-0x%x, msg id:%d\r\n", diff, diff1, nonce, g_msgIdx);

  uint64_t n[64];
  ncnt = drv_get_nonce(&msgidx, (uint8_t *)&n[0]);
  if(ncnt == 0)
    return 0;

  int v_cnt = 0;
  uint32_t _ALIGN(64) edata[20];
  uint32_t vdata[20*4] __attribute__ ((aligned (64)));
  uint32_t *noncep = vdata + 76;

  swab32_array( edata, g_u32Work, 20 );
  mm_interleave_4x32( vdata, edata, edata, edata, edata, 640 );

  blake256_4way_init( &l2v2_4way_ctx.blake );
  blake256_4way( &l2v2_4way_ctx.blake, vdata, 64 );

  for (int i = 0; i < ncnt; i++) {
    uint32_t tn = n[i];

    be32enc( noncep,   tn   );
    be32enc( noncep+1, tn+1 );
    be32enc( noncep+2, tn+2 );
    be32enc( noncep+3, tn+3 );
    lyra2rev2_4way_hash( hash, vdata );

    uint8_t coreId = (tn >> 18) & 0x3f;
    uint8_t td = _get_leadingZeroCnt((uint8_t *)hash);
    if (td > g_u32MaxDiff) g_u32MaxDiff = td;
    //if(fulltest( hash, ptarget)) {
    if (td >= diff) {
      pdata[19] = tn;
      work->nonces[v_cnt++] = tn;
      work_set_target_ratio(work, hash);
      //if (td >= diff) 
      g_u32Ncnt += 1;
      printf("############## find valid nonce: 0x%08x, diff:%d, core:%d\r\n", tn, td, coreId);
    } else {
      printf("error nonce:0x%08x, diff:%d, expect:%d, core:%d, validate submit:%d, maxdiff:%d\r\n", tn, td, diff, coreId, g_u32Ncnt, g_u32MaxDiff);
      //print8u("hash0 output", hash, 32);
    }

    *hashes_done = ((tn & 0xff03ffff) - nonce) * 16;
  }

  g_msgIdx += 1;
  return v_cnt;
}
#else

#if __FECTH_DATA
static uint32_t w[20] = {
  0xa88c6e5c, 0x00007fd6, 0x5aabb994, 0x00005585, 0xa88c6ff0, 0x00007fd6, 0x5aab9858, 0x00005585,
  0x900011a0, 0x00007fd6, 0x5bfc5dc0, 0x00005585, 0x5bfc5dd0, 0x00005585, 0xb194fefa, 0x00007fd6,
  0x00000030, 0x00000030, 0xa88c6e98, 0x00000000
};
#endif

int scanhash_lyra2rev2_4way( int thr_id, struct work *work, uint32_t max_nonce,
                             uint64_t *hashes_done )
{
   uint32_t hash[8*4] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t _ALIGN(64) edata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   const uint32_t Htarg = ptarget[7];
   uint32_t *nonces = work->nonces;
   int num_found = 0;
   uint32_t *noncep = vdata + 76; // 19*4

   if ( opt_benchmark )
      ( (uint32_t*)ptarget )[7] = 0x0000ff;

  #if __FECTH_DATA
  memcpy(pdata, w, 80);
  memset(pdata, 0, 80);
  n = 0x14d45;
  printv("work", pdata, 20);
  #endif
   swab32_array( edata, pdata, 20 );
   mm_interleave_4x32( vdata, edata, edata, edata, edata, 640 );

   blake256_4way_init( &l2v2_4way_ctx.blake );
   blake256_4way( &l2v2_4way_ctx.blake, vdata, 64 );

   do {
      #if __FECTH_DATA
      printv("nonce", &n, 1);
      #endif
      be32enc( noncep,   n   );
      be32enc( noncep+1, n+1 );
      be32enc( noncep+2, n+2 );
      be32enc( noncep+3, n+3 );

      lyra2rev2_4way_hash( hash, vdata );
      #if __FECTH_DATA
      printv("hash0 output", hash, 8);
      printv("hash1 output", hash+8, 8);
      printv("hash2 output", hash+16, 8);
      printv("hash3 output", hash+24, 8);
      #endif
      pdata[19] = n;

      for ( int i = 0; i < 4; i++ )
      if ( (hash+(i<<3))[7] <= Htarg && fulltest( hash+(i<<3), ptarget ) )
      {
          pdata[19] = n+i;
          nonces[ num_found++ ] = n+i;
          work_set_target_ratio( work, hash+(i<<3) );
      }
      n += 4;
      #if __FECTH_DATA
      sleep(1);
      #endif
   } while ( (num_found == 0) && (n < max_nonce-4)
                   && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce + 1;
   return num_found;
}

#endif
#endif
