
#ifdef MEASURE
#define _GNU_SOURCE
#include <inttypes.h>
#include <sys/types.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#endif
#include <sodium.h>
#include <string.h>


#include "crypto_cpace.h"

#define DSI1 "CPaceRistretto255-1"
#define DSI2 "CPaceRistretto255-2"
#define session_id_BYTES 16
#define hash_BLOCKSIZE 128

#define COMPILER_ASSERT(X) (void) sizeof(char[(X) ? 1 : -1])

#ifdef MEASURE
struct perf_event_attr perf_pe_instr_cpace;
struct perf_event_attr perf_pe_cycles_cpace;
long long count;
int perf_fd_cpace;
static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
	int ret;
	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
}

#define TOTAL_EVENTS 2
struct read_format {
	uint64_t nr;
	struct {
		uint64_t value;
		uint64_t id;
	} values[TOTAL_EVENTS];
};

struct read_format counter_results_cpace;

static void finish_perf_msmt()
{
	ioctl(perf_fd_cpace, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
	read(perf_fd_cpace, &counter_results_cpace, sizeof(struct read_format));
	printf("CPACE_CRYPTO: Used %lld instructions\n", counter_results_cpace.values[0].value);
	printf("CPACE_CRYPTO: Used %lld cpu cycles\n", counter_results_cpace.values[1].value);
}
#endif

static int
ctx_init(crypto_cpace_state *const ctx, const char *password,
         size_t password_len, const char *id_a, unsigned char id_a_len,
         const char *id_b, unsigned char id_b_len, const unsigned char *ad,
         size_t ad_len)
{
    crypto_hash_sha512_state st;
    unsigned char            h[crypto_core_ristretto255_HASHBYTES];
    static unsigned char     zpad[hash_BLOCKSIZE];
    const size_t             dsi_len = sizeof DSI1 - 1U;
    size_t                   pad_len;

    COMPILER_ASSERT(sizeof ctx->session_id == session_id_BYTES &&
                    sizeof ctx->p == crypto_scalarmult_ristretto255_BYTES &&
                    sizeof ctx->r ==
                        crypto_scalarmult_ristretto255_SCALARBYTES);
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, (const unsigned char *) DSI1, dsi_len);
    crypto_hash_sha512_update(&st, (const unsigned char *) password,
                              password_len);
    pad_len = sizeof zpad - (dsi_len + password_len) & (sizeof zpad - 1);
    crypto_hash_sha512_update(&st, zpad, pad_len);
    crypto_hash_sha512_update(&st, ctx->session_id, session_id_BYTES);
    crypto_hash_sha512_update(&st, &id_a_len, 1);
    crypto_hash_sha512_update(&st, (const unsigned char *) id_a, id_a_len);
    crypto_hash_sha512_update(&st, &id_b_len, 1);
    crypto_hash_sha512_update(&st, (const unsigned char *) id_b, id_b_len);
    crypto_hash_sha512_update(&st, ad, ad_len);
    COMPILER_ASSERT(crypto_core_ristretto255_HASHBYTES ==
                    crypto_hash_sha512_BYTES);
    crypto_hash_sha512_final(&st, h);

    crypto_core_ristretto255_from_hash(ctx->p, h);
    crypto_core_ristretto255_scalar_random(ctx->r);

    return crypto_scalarmult_ristretto255(ctx->p, ctx->r, ctx->p);
}

static int
ctx_final(const crypto_cpace_state *ctx, crypto_cpace_shared_keys *shared_keys,
          const unsigned char op[crypto_scalarmult_ristretto255_BYTES],
          const unsigned char ya[crypto_scalarmult_ristretto255_BYTES],
          const unsigned char yb[crypto_scalarmult_ristretto255_BYTES])
{
    crypto_hash_sha512_state st;
    unsigned char            p[crypto_scalarmult_ristretto255_BYTES];
    unsigned char            h[crypto_hash_sha512_BYTES];

    /* crypto_scalarmult_*() rejects the identity element */
    if (crypto_scalarmult_ristretto255(p, ctx->r, op) != 0) {
        return -1;
    }
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, (const unsigned char *) DSI2,
                              sizeof DSI2 - 1);
    crypto_hash_sha512_update(&st, ctx->session_id, session_id_BYTES);
    crypto_hash_sha512_update(&st, p, crypto_scalarmult_ristretto255_BYTES);
    crypto_hash_sha512_update(&st, ya, crypto_scalarmult_ristretto255_BYTES);
    crypto_hash_sha512_update(&st, yb, crypto_scalarmult_ristretto255_BYTES);
    crypto_hash_sha512_final(&st, h);
    COMPILER_ASSERT(sizeof h >= 2 * crypto_cpace_SHAREDKEYBYTES);
    memcpy(shared_keys->client_sk, h, crypto_cpace_SHAREDKEYBYTES);
    memcpy(shared_keys->server_sk, h + crypto_cpace_SHAREDKEYBYTES,
           crypto_cpace_SHAREDKEYBYTES);

    return 0;
}

int
crypto_cpace_init(void)
{
    COMPILER_ASSERT(
        crypto_cpace_RESPONSEBYTES == crypto_scalarmult_ristretto255_BYTES &&
        crypto_cpace_PUBLICDATABYTES ==
            session_id_BYTES + crypto_scalarmult_ristretto255_BYTES);

#ifdef MEASURE
	 memset(&perf_pe_instr_cpace, 0, sizeof(struct perf_event_attr));
	 perf_pe_instr_cpace.type = PERF_TYPE_HARDWARE;
	 perf_pe_instr_cpace.size = sizeof(struct perf_event_attr);
	 perf_pe_instr_cpace.config = PERF_COUNT_HW_INSTRUCTIONS;
	 perf_pe_instr_cpace.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_ID;
	 perf_pe_instr_cpace.disabled = 1;
	 perf_pe_instr_cpace.exclude_kernel = 1;
	 // Don't count hypervisor events.
	 perf_pe_instr_cpace.exclude_hv = 1;

	 memset(&perf_pe_cycles_cpace, 0, sizeof(struct perf_event_attr));
	 perf_pe_cycles_cpace.type = PERF_TYPE_HARDWARE;
	 perf_pe_cycles_cpace.size = sizeof(struct perf_event_attr);
	 perf_pe_cycles_cpace.config = PERF_COUNT_HW_CPU_CYCLES;
	 perf_pe_cycles_cpace.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_ID;
	 perf_pe_cycles_cpace.disabled = 1;
	 perf_pe_cycles_cpace.exclude_kernel = 1;
	 // Don't count hypervisor events.
	 perf_pe_cycles_cpace.exclude_hv = 1;

	 perf_fd_cpace = perf_event_open(&perf_pe_instr_cpace, 0, -1, -1, 0); /* Leader */
	 if (perf_fd_cpace == -1) {
		 fprintf(stderr, "Error opening leader %llx\n", perf_pe_instr_cpace.config);
		 exit(EXIT_FAILURE);
	 }
	 int res = perf_event_open(&perf_pe_cycles_cpace, 0, -1, perf_fd_cpace, 0);
	 if (res == -1) {
		 fprintf(stderr, "Error opening follower %llx\n", perf_pe_cycles_cpace.config);
		 exit(EXIT_FAILURE);
	 }
#endif

    return sodium_init();
}

int
crypto_cpace_step1(crypto_cpace_state *ctx,
                   unsigned char public_data[crypto_cpace_PUBLICDATABYTES],
                   const char *password, size_t password_len, const char *id_a,
                   unsigned char id_a_len, const char *id_b,
                   unsigned char id_b_len, const unsigned char *ad,
                   size_t ad_len

)
{

#ifdef MEASURE
	ioctl(perf_fd_cpace, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
	ioctl(perf_fd_cpace, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
#endif
    randombytes_buf(ctx->session_id, session_id_BYTES);
    if (ctx_init(ctx, password, password_len, id_a, id_a_len, id_b, id_b_len,
                 ad, ad_len) != 0) {
#ifdef MEASURE
	finish_perf_msmt();
#endif
        return -1;
    }
    memcpy(public_data, ctx->session_id, session_id_BYTES);
    memcpy(public_data + session_id_BYTES, ctx->p,
           crypto_scalarmult_ristretto255_BYTES);

#ifdef MEASURE
	finish_perf_msmt();
#endif
    return 0;
}

int
crypto_cpace_step2(
    unsigned char             response[crypto_cpace_RESPONSEBYTES],
    const unsigned char       public_data[crypto_cpace_PUBLICDATABYTES],
    crypto_cpace_shared_keys *shared_keys, const char *password,
    size_t password_len, const char *id_a, unsigned char id_a_len,
    const char *id_b, unsigned char id_b_len, const unsigned char *ad,
    size_t ad_len)
{
#ifdef MEASURE
	ioctl(perf_fd_cpace, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
	ioctl(perf_fd_cpace, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
#endif
    crypto_cpace_state   ctx;
    const unsigned char *ya = public_data + session_id_BYTES;

    memcpy(ctx.session_id, public_data, session_id_BYTES);
    if (ctx_init(&ctx, password, password_len, id_a, id_a_len, id_b, id_b_len,
                 ad, ad_len) != 0) {
#ifdef MEASURE
	finish_perf_msmt();
#endif
        return -1;
    }
    memcpy(response, ctx.p, crypto_scalarmult_ristretto255_BYTES);
    if (ctx_final(&ctx, shared_keys, ya, ya, response) != 0) {

#ifdef MEASURE
	finish_perf_msmt();
#endif
        return -1;
    }
    sodium_memzero(&ctx, sizeof ctx);
#ifdef MEASURE
	finish_perf_msmt();
#endif

    return 0;
}

int
crypto_cpace_step3(crypto_cpace_state *      ctx,
                   crypto_cpace_shared_keys *shared_keys,
                   const unsigned char response[crypto_cpace_RESPONSEBYTES])
{
    return ctx_final(ctx, shared_keys, response, ctx->p, response);
}
