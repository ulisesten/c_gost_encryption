/**
 *  @file  benchmark.c
 *  @brief  Throughput of the content-encryption features on this
 *          machine: Kuznyechik, CTR-ACPKM, CMAC, AEAD and SFrame.
 *
 *  Numbers are MB/s of payload.  Run on the target platform before
 *  fixing video resolution or bitrates; see REQUIREMENTS.md section 7.
 */
#include <gost/gost.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

/** Payload per measurement round. */
#define BENCH_BUFFER (64U * 1024U)

/** Minimum seconds per measurement. */
#define BENCH_SECONDS 1.0

static double monotonic_seconds(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)now.tv_sec + (double)now.tv_nsec / 1e9;
}

/**
 *  @brief  Measure a callback over @p bytes of payload, repeatedly
 *          until BENCH_SECONDS elapsed; returns MB/s.
 */
static double throughput(const char *label, gost_status_t (*work)(void), size_t bytes)
{
    unsigned rounds = 0U;
    double start = monotonic_seconds();
    double elapsed = 0.0;
    do {
        if (work() != GOST_OK) {
            printf("%-22s failed\n", label);
            return 0.0;
        }
        rounds++;
        elapsed = monotonic_seconds() - start;
    } while (elapsed < BENCH_SECONDS);
    double mbps = (double)rounds * (double)bytes / elapsed / (1024.0 * 1024.0);
    printf("%-22s %8.1f MB/s\n", label, mbps);
    return mbps;
}

static uint8_t bench_key[32];
static uint8_t bench_icn[8];
static uint8_t bench_nonce[16];
static uint8_t bench_plain[BENCH_BUFFER];
static uint8_t bench_cipher[BENCH_BUFFER + 64U];
static uint8_t bench_tag[16];
static gost_kuznyechik_t bench_schedule;
static gost_sframe_ctx_t bench_sframe_state;
static size_t bench_wire_len;

static gost_status_t bench_kuznyechik(void)
{
    uint8_t block[16];
    for (unsigned i = 0; i < BENCH_BUFFER / 16U; i++) {
        gost_kuznyechik_encrypt_block(&bench_schedule, bench_plain + 16U * i, block);
    }
    return GOST_OK;
}

static gost_status_t bench_ctr(void)
{
    return gost_ctr_acpkm(bench_key, bench_icn, 0U, bench_plain, bench_cipher, BENCH_BUFFER);
}

static gost_status_t bench_cmac(void)
{
    return gost_cmac(bench_key, bench_plain, BENCH_BUFFER, bench_tag);
}

static gost_status_t bench_aead(void)
{
    return gost_aead_seal(bench_key, bench_nonce, bench_plain, 16U, bench_plain, BENCH_BUFFER,
                          bench_cipher, bench_tag);
}

static gost_status_t bench_sframe(void)
{
    return gost_sframe_encrypt(&bench_sframe_state, bench_plain, BENCH_BUFFER, bench_cipher,
                               sizeof(bench_cipher), &bench_wire_len);
}

int main(void)
{
    for (unsigned i = 0; i < sizeof(bench_key); i++) {
        bench_key[i] = (uint8_t)(i * 5U + 1U);
    }
    memset(bench_icn, 0x42, sizeof(bench_icn));
    memcpy(bench_nonce, bench_icn, sizeof(bench_icn));
    for (unsigned i = 0; i < BENCH_BUFFER; i++) {
        bench_plain[i] = (uint8_t)i;
    }
    gost_kuznyechik_init(&bench_schedule, bench_key);
    gost_sframe_init(&bench_sframe_state);
    gost_sframe_set_key(&bench_sframe_state, 1U, bench_key);

    printf("gost benchmarks, payload %u KiB:\n", BENCH_BUFFER / 1024U);
    throughput("kuznyechik ecb", bench_kuznyechik, BENCH_BUFFER);
    throughput("ctr-acpkm 4k sec", bench_ctr, BENCH_BUFFER);
    throughput("cmac-128", bench_cmac, BENCH_BUFFER);
    throughput("aead seal", bench_aead, BENCH_BUFFER);
    throughput("sframe seal", bench_sframe, BENCH_BUFFER);
    return 0;
}
