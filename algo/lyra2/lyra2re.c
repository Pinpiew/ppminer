#include <memory.h>

#include "algo/blake/sph_blake.h"
#include "algo/groestl/sph_groestl.h"
#include "algo/skein/sph_skein.h"
#include "algo/keccak/sph_keccak.h"
#include "lyra2.h"
#include "algo-gate-api.h"
#include "avxdefs.h"
#include "drv_api.h"
#ifndef NO_AES_NI
  #include "algo/groestl/aes_ni/hash-groestl256.h"
#endif

//__thread uint64_t* lyra2re_wholeMatrix;

typedef struct {
        sph_blake256_context     blake;
        sph_keccak256_context    keccak;
        sph_skein256_context     skein;
#ifdef NO_AES_NI
        sph_groestl256_context   groestl;
#else
        hashState_groestl256     groestl;
#endif
} lyra2re_ctx_holder;

lyra2re_ctx_holder lyra2re_ctx;
static __thread sph_blake256_context lyra2_blake_mid;

void init_lyra2re_ctx()
{
        sph_blake256_init(&lyra2re_ctx.blake);
        sph_keccak256_init(&lyra2re_ctx.keccak);
        sph_skein256_init(&lyra2re_ctx.skein);
#ifdef NO_AES_NI
        sph_groestl256_init(&lyra2re_ctx.groestl);
#else
        init_groestl256( &lyra2re_ctx.groestl, 32 );
#endif
}

void lyra2_blake256_midstate( const void* input )
{
    memcpy( &lyra2_blake_mid, &lyra2re_ctx.blake, sizeof lyra2_blake_mid );
    sph_blake256( &lyra2_blake_mid, input, 64 );
}

void lyra2re_hash(void *state, const void *input)
{
        lyra2re_ctx_holder ctx __attribute__ ((aligned (64))) ;
        memcpy(&ctx, &lyra2re_ctx, sizeof(lyra2re_ctx));

	uint8_t _ALIGN(64) hash[32*8];
        #define hashA hash
        #define hashB hash+16

        const int midlen = 64;            // bytes
        const int tail   = 80 - midlen;   // 16

        memcpy( &ctx.blake, &lyra2_blake_mid, sizeof lyra2_blake_mid );
        sph_blake256( &ctx.blake, input + midlen, tail );

	sph_blake256_close(&ctx.blake, hashA);

	sph_keccak256(&ctx.keccak, hashA, 32);
	sph_keccak256_close(&ctx.keccak, hashB);

        LYRA2RE( hashA, 32, hashB, 32, hashB, 32, 1, 8, 8);
//	LYRA2RE( lyra2re_wholeMatrix, hashA, 32, hashB, 32, hashB, 32, 1, 8, 8);

	sph_skein256(&ctx.skein, hashA, 32);
	sph_skein256_close(&ctx.skein, hashB);

#ifdef NO_AES_NI
	sph_groestl256( &ctx.groestl, hashB, 32 );
	sph_groestl256_close( &ctx.groestl, hashA );
#else
        update_and_final_groestl256( &ctx.groestl, hashA, hashB, 256 );
#endif

	memcpy(state, hashA, 32);
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
int scanhash_lyra2re(int thr_id, struct work *work,
	uint32_t max_nonce,	uint64_t *hashes_done)
{
  uint32_t *pdata = work->data;
  uint32_t *ptarget = work->target;
  uint32_t _ALIGN(64) endiandata[20];
  uint32_t hash[8] __attribute__((aligned(64)));
  const uint32_t first_nonce = pdata[19];
  uint32_t nonce = first_nonce;
  //const uint32_t Htarg = ptarget[7];

  uint8_t diff = _get_leadingZeroCnt((uint8_t *)ptarget);
  uint8_t diff1 = diff > 10 ? 15 : diff;
  if (memcmp((uint8_t *)&endiandata[0], g_u32Work, 76) != 0) {

    memcpy(g_u32Work, (uint8_t *)&endiandata[0], 76);
    g_u32Work[19] = nonce;
    printf("**************new work,%d, diff:%d\n", g_msgIdx, diff);

    drv_send_work(g_msgIdx, diff1, (uint8_t *)&nonce, 4, (uint8_t *)g_u32Work, 80);
    printv("work", g_u32Work, 20);
  }

  uint64_t n[64];
  uint8_t msgidx;
  int ncnt = drv_get_nonce(&msgidx, (uint8_t *)&n[0]);
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

    swab32_array( tm, g_u32Work, 20 );
    lyra2_blake256_midstate( tm );
    be32enc(&tm[19], tn);
    lyra2re_hash( hash, tm);

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

int scanhash_lyra2re(int thr_id, struct work *work,
	uint32_t max_nonce,	uint64_t *hashes_done)
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	uint32_t _ALIGN(64) endiandata[20];
        uint32_t hash[8] __attribute__((aligned(64)));
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
        const uint32_t Htarg = ptarget[7];

        #if 1
        memcpy(pdata, w, 80);
        nonce = 0x14d45;
        printv("work", pdata, 20);
        #endif
        swab32_array( endiandata, pdata, 20 );

        lyra2_blake256_midstate( endiandata );

	do {
      printv("nonce", &nonce, 1);
		be32enc(&endiandata[19], nonce);
		lyra2re_hash(hash, endiandata);
        printv("\nhash output", hash, 8);
		if (hash[7] <= Htarg )
                {
                   if ( fulltest(hash, ptarget) )
                   {
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
                        work_set_target_ratio( work, hash );
			return 1;
                   }
		}
		nonce++;

	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}
#endif

int64_t lyra2re_get_max64 ()
{
  return 0xffffLL;
}

void lyra2re_set_target ( struct work* work, double job_diff )
{
   work_set_target(work, job_diff / (128.0 * opt_diff_factor) );
}

bool register_lyra2re_algo( algo_gate_t* gate )
{
  init_lyra2re_ctx();
  gate->optimizations = SSE2_OPT | AES_OPT | SSE42_OPT | AVX2_OPT;
  gate->scanhash   = (void*)&scanhash_lyra2re;
  gate->hash       = (void*)&lyra2re_hash;
  gate->get_max64  = (void*)&lyra2re_get_max64;
  gate->set_target = (void*)&lyra2re_set_target;
  return true;
};
