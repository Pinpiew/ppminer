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

static void printv( const uint8_t *str, uint32_t *v, uint32_t len) {

  printf( "%s:", str);
  for( uint32_t i=0; i<len; i++) {

    if( ( i%8) == 0) printf( "\n");
    printf( "%08x ", v[ i]);
  }
  printf( "\n\n");
}

static uint32_t g_u32Work[20];

#if 0
int scanhash_lyra2rev2(int thr_id, struct work *work,
	uint32_t max_nonce, uint64_t *hashes_done)
{
  uint32_t *pdata = work->data;
  uint32_t *ptarget = work->target;
  uint32_t endiandata[20] __attribute__ ((aligned (64)));
  uint32_t hash[8] __attribute__((aligned(64)));
  const uint32_t first_nonce = (pdata[19] + 15) & 0xfffffff0;
  uint32_t nonce = (first_nonce + 15) & 0xfffffff0;
  const uint32_t Htarg = ptarget[7];
  uint8_t msgidx;
  int ncnt;

  //printf("%s, %d: 0x%08x, 0x%08x, 0x%08x,0x%08x\n", __FUNCTION__, __LINE__, ptarget[7], ptarget[6], ptarget[5], ptarget[4]);
  if (opt_benchmark)
    ((uint32_t*)ptarget)[7] = 0x0000ff;

  uint8_t diff = _get_leadingZeroCnt((uint8_t *)ptarget);
  uint8_t diff1 = diff > 10 ? 15 : diff;
  if (memcmp((uint8_t *)&endiandata[0], g_u32Work, 76) != 0) {

    memcpy(g_u32Work, (uint8_t *)&endiandata[0], 76);
    g_u32Work[19] = nonce;
    printf("**************new work,%d\n", g_msgIdx);

    drv_send_work(g_msgIdx, diff1, (uint8_t *)&nonce, 4, (uint8_t *)g_u32Work, 80);
    printv("work", g_u32Work, 20);
  }

  //printf("work: diff-%d %d, nonce-0x%x, msg id:%d\r\n", diff, diff1, nonce, g_msgIdx);

  uint64_t n[64];
  ncnt = drv_get_nonce(&msgidx, (uint8_t *)&n[0]);
  if(ncnt == 0)
    return 0;

  if ( ncnt == 1)
    printf("rx %d nonce, 1st nonce:0x%08lx\n", ncnt, n[0]);
  else
    printf("rx %d nonce, 1st nonce:0x%08lx, 2nd:0x%08lx\n", ncnt, n[0], n[1]);

  int v_cnt = 0;
  for (int i = 0; i < ncnt; i++) {
    uint32_t tm[20];
    uint32_t tn = n[i];
    memcpy(tm, g_u32Work, 80);
    //be32enc( &tm[19], tn);
    tm[19] = tn;

    swab32_array( tm, g_u32Work, 20 );
    l2v2_blake256_midstate( tm );
    be32enc(&tm[19], tn);
    lyra2rev2_hash( hash, tm);

    uint8_t td = _get_leadingZeroCnt((uint8_t *)hash);
    //if(fulltest( hash, ptarget)) {
    if (1) {  //(td >= diff1) {
      work->nonces[v_cnt] = tn;
      v_cnt +=1;
      printf("#### find valid nonce: 0x%08x, diff:%d\r\n", tn, td);
    } else {
      printf("error nonce:0x%08x, diff:%d\n", tn, td);
    }
  }

  g_msgIdx += 1;
  return v_cnt;
}
#else
static uint32_t w[20] = {
  0xa88c6e5c, 0x00007fd6, 0x5aabb994, 0x00005585, 0xa88c6ff0, 0x00007fd6, 0x5aab9858, 0x00005585,
  0x900011a0, 0x00007fd6, 0x5bfc5dc0, 0x00005585, 0x5bfc5dd0, 0x00005585, 0xb194fefa, 0x00007fd6,
  0x00000030, 0x00000030, 0xa88c6e98, 0x00000000
};

int scanhash_lyra2rev2( int thr_id, struct work *work,
                        uint32_t max_nonce, uint64_t *hashes_done)
{
  uint32_t *pdata = work->data;
  uint32_t *ptarget = work->target;
  uint32_t endiandata[ 20] __attribute__ ( ( aligned ( 64)));
  uint32_t hash[ 8] __attribute__( ( aligned( 64)));
  const uint32_t first_nonce = pdata[ 19];
  uint32_t nonce = first_nonce;
  const uint32_t Htarg = ptarget[ 7];

  if ( opt_benchmark)
    ( ( uint32_t*)ptarget)[ 7] = 0x0000ff;

  #if 0
  memcpy(pdata, w, 80);
  nonce = 0x14d45;
  printv("work", pdata, 20);
  #endif
  swab32_array(  endiandata, pdata, 20 );
  l2v2_blake256_midstate(  endiandata );

  do {
    //printv("nonce", &nonce, 1);
    be32enc( &endiandata[ 19], nonce);
    lyra2rev2_hash( hash, endiandata);
    //printv("\nhash output", hash, 8);
    if ( hash[ 7] <= Htarg ) {

      if(  fulltest( hash, ptarget) ) {
        pdata[ 19] = nonce;
        work_set_target_ratio(  work, hash );
        *hashes_done = pdata[ 19] - first_nonce;
        return 1;
      }
    }

    nonce++;
    //sleep(1);
  } while ( nonce < max_nonce && !work_restart[ thr_id].restart);

  pdata[ 19] = nonce;
  *hashes_done = pdata[ 19] - first_nonce + 1;
  return 0;
}
#endif
