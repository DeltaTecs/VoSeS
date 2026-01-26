#include "tls13-extractor.h"
#include "tls13-gcm-extract.h"
#include "../common/extractor-common.h"
#include "../../cuda_util.h"
#include <cuda_runtime.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#define TLS13_APP_TRAFFIC_SECRET_0_LEN_SHA256 32
#define TLS13_APP_TRAFFIC_SECRET_0_LEN_SHA384 48
#define TLS13_AAD_LEN 5
#define TLS13_MAX_CIPHERTEXT_LEN 16384

__device__ __constant__ unsigned char d_tls13_const_aad[TLS13_AAD_LEN];
__device__ __constant__ unsigned char d_tls13_const_ciphertext[TLS13_MAX_CIPHERTEXT_LEN];
__device__ __constant__ short d_tls13_const_ciphertext_length;

#define CUDA_CHECK(err, msg)            \
    do {                                \
        if ((err) != cudaSuccess) {     \
            printf("%s: %s\n", msg, cudaGetErrorString(err));  \
            return false;               \
        }                               \
    } while (0)

__global__ void tls13_app_traffic_secret_0_scan_gcm128_sha256_kernel(const unsigned char* d_haystack, const uint64_t haystack_length,
                                                            const char percentile, uint64_t seq_num,
                                                            const float entropyThreshold, unsigned long long* d_addr_found) {

    const unsigned long thread_index = blockIdx.x * blockDim.x + threadIdx.x;
    const uint64_t percentile_index = (percentile * blockDim.x * gridDim.x + thread_index) * d_memory_alignment;

    if (percentile_index + 1 + TLS13_APP_TRAFFIC_SECRET_0_LEN_SHA256 > haystack_length) {
        return;
    }

    unsigned char candidate[TLS13_APP_TRAFFIC_SECRET_0_LEN_SHA256];
    cuda_array_copy(candidate, d_haystack + percentile_index, TLS13_APP_TRAFFIC_SECRET_0_LEN_SHA256);
    float entropy = calculateEntropy(candidate, TLS13_APP_TRAFFIC_SECRET_0_LEN_SHA256);

    if (entropy < entropyThreshold) {
        return;
    }

    bool isMatch = cuda_match_app_traffic_secret_0_gcm128_sha256(candidate, TLS13_APP_TRAFFIC_SECRET_0_LEN_SHA256,
                                                                 seq_num, d_tls13_const_aad, TLS13_AAD_LEN,
                                                                 d_tls13_const_ciphertext, d_tls13_const_ciphertext_length);
    if (isMatch) {
        printf("\nMatch has entropy %f\n", entropy);
        *d_addr_found = percentile_index;
    }
}

__global__ void tls13_app_traffic_secret_0_scan_gcm256_sha384_kernel(const unsigned char* d_haystack, const uint64_t haystack_length,
                                                            const char percentile, uint64_t seq_num,
                                                            const float entropyThreshold, unsigned long long* d_addr_found) {

    const unsigned long thread_index = blockIdx.x * blockDim.x + threadIdx.x;
    const uint64_t percentile_index = (percentile * blockDim.x * gridDim.x + thread_index) * d_memory_alignment;

    if (percentile_index + 1 + TLS13_APP_TRAFFIC_SECRET_0_LEN_SHA384 > haystack_length) {
        return;
    }

    unsigned char candidate[TLS13_APP_TRAFFIC_SECRET_0_LEN_SHA384];
    cuda_array_copy(candidate, d_haystack + percentile_index, TLS13_APP_TRAFFIC_SECRET_0_LEN_SHA384);
    float entropy = calculateEntropy(candidate, TLS13_APP_TRAFFIC_SECRET_0_LEN_SHA384);

    if (entropy < entropyThreshold) {
        return;
    }

    bool isMatch = cuda_match_app_traffic_secret_0_gcm256_sha384(candidate, TLS13_APP_TRAFFIC_SECRET_0_LEN_SHA384,
                                                                 seq_num, d_tls13_const_aad, TLS13_AAD_LEN,
                                                                 d_tls13_const_ciphertext, d_tls13_const_ciphertext_length);
    if (isMatch) {
        printf("\nMatch has entropy %f\n", entropy);
        *d_addr_found = percentile_index;
    }
}

__host__ unsigned long long tls13_app_traffic_secret_0_helper(const unsigned char* haystack, const uint64_t haystack_length,
                                                             unsigned char* app_data_record, int app_data_record_length,
                                                             uint64_t seq_num, unsigned char client_random[32],
                                                             const float entropyThreshold, const bool client,
                                                             const int secret_len,
                                                             void (*search_kernel) (const unsigned char*, const uint64_t,
                                                                     const char, uint64_t,
                                                                     const float, unsigned long long*)) {

    if (app_data_record_length < TLS13_AAD_LEN) {
        printf("ERROR app_data_record too short for TLS 1.3 header.\n");
        return k_addr_not_found;
    }

    unsigned char* aad_bytes = (unsigned char*) malloc(TLS13_AAD_LEN);
    memcpy(aad_bytes, app_data_record, TLS13_AAD_LEN);

    int ciphertext_len = app_data_record_length - TLS13_AAD_LEN;
    uint16_t record_len = (static_cast<uint16_t>(app_data_record[3]) << 8) |
                          static_cast<uint16_t>(app_data_record[4]);
    if (record_len != ciphertext_len) {
        printf("WARNING TLS 1.3 record length mismatch: header %u vs buffer %d\n", record_len, ciphertext_len);
        if (record_len < ciphertext_len) {
            ciphertext_len = record_len;
        }
    }

    if (ciphertext_len <= 0) {
        printf("ERROR app_data_record missing ciphertext.\n");
        free(aad_bytes);
        return k_addr_not_found;
    }

    if (ciphertext_len > TLS13_MAX_CIPHERTEXT_LEN) {
        printf("ERROR ciphertext length %d exceeds constant memory limit %d.\n", ciphertext_len, TLS13_MAX_CIPHERTEXT_LEN);
        free(aad_bytes);
        return k_addr_not_found;
    }

    unsigned char* ciphertext_bytes = (unsigned char*) malloc(ciphertext_len);
    memcpy(ciphertext_bytes, app_data_record + TLS13_AAD_LEN, ciphertext_len);

    unsigned long long h_addr_found = k_addr_not_found;

    unsigned char *d_haystack = nullptr;
    unsigned long long* d_addr_found = nullptr;

    cudaError_t err;
    err = cudaMalloc((void**)&d_haystack, haystack_length);
    CUDA_CHECK(err, "cudaMalloc failed for d_haystack");
    err = cudaMalloc((void**)&d_addr_found, sizeof(unsigned long long));
    CUDA_CHECK(err, "cudaMalloc failed for d_addr_found");

    err = cudaMemcpy(d_haystack, haystack, haystack_length, cudaMemcpyHostToDevice);
    CUDA_CHECK(err, "cudaMemcpy failed for d_haystack");

    // Copy AAD and ciphertext to constant memory
    err = cudaMemcpyToSymbol(d_tls13_const_aad, aad_bytes, TLS13_AAD_LEN * sizeof(unsigned char));
    CUDA_CHECK(err, "cudaMemcpyToSymbol failed for d_tls13_const_aad");
    err = cudaMemcpyToSymbol(d_tls13_const_ciphertext, ciphertext_bytes, ciphertext_len * sizeof(unsigned char));
    CUDA_CHECK(err, "cudaMemcpyToSymbol failed for d_tls13_const_ciphertext");
    short h_ciphertext_len = (short)ciphertext_len;
    err = cudaMemcpyToSymbol(d_tls13_const_ciphertext_length, &h_ciphertext_len, sizeof(short));
    CUDA_CHECK(err, "cudaMemcpyToSymbol failed for d_tls13_const_ciphertext_length");

    err = cudaMemset(d_addr_found, 0xFF, sizeof(unsigned long long));
    CUDA_CHECK(err, "cudaMemset failed for d_addr_found");

    cudaFuncAttributes attr;
    cudaFuncGetAttributes(&attr, search_kernel);

    int min_grid_size = 0, block_size = 0;
    cudaOccupancyMaxPotentialBlockSize(&min_grid_size, &block_size, search_kernel, 0, 0);

    int max_threads_per_block = attr.maxThreadsPerBlock;

    uint64_t candidates_per_percentile = haystack_length / (100 * get_memory_alignment());
    long num_blocks = (candidates_per_percentile + max_threads_per_block - 1) / max_threads_per_block;
    
    printf("#### launch parameters: min gid: %d, min block %d, max threads %d, num blocks: %ld, num threads: %d\n",
        min_grid_size, block_size, max_threads_per_block, num_blocks, max_threads_per_block);

    printf("  Registers per thread: %d\n", attr.numRegs);
    printf("  Local memory per thread: %zu bytes\n", attr.localSizeBytes);
    printf("  Shared memory per block: %zu bytes\n", attr.sharedSizeBytes);
    printf("  Constant memory usage: %zu bytes\n", attr.constSizeBytes);
    printf("  Max threads per block: %d\n", attr.maxThreadsPerBlock);
    printf("  PTX version: %d\n", attr.ptxVersion);
    printf("  Binary version: %d\n", attr.binaryVersion);

    cudaEvent_t start, stop;
    float milliseconds = 0;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start);

    for (int i = 0; i < 100; i++) {
        printf("\rapp traffic secret scan %d%%", i);
        fflush(stdout);
        search_kernel<<<num_blocks, max_threads_per_block>>>(d_haystack, haystack_length, i,
            seq_num, entropyThreshold, d_addr_found);
        cudaDeviceSynchronize();
        err = cudaGetLastError();
        if (err != cudaSuccess) printf("Kernel launch error: %s\n", cudaGetErrorString(err));

        err = cudaMemcpy(&h_addr_found, d_addr_found, sizeof(unsigned long long), cudaMemcpyDeviceToHost);
        CUDA_CHECK(err, "cudaMemcpy failed for d_addr_found to host");
        if (h_addr_found != k_addr_not_found) break;
    }

    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&milliseconds, start, stop);
    printf("\nscan runtime %.3f ms\n", milliseconds);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);

    err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("ERROR Kernel launch error: %s\n", cudaGetErrorString(err));
    }

    cudaFree(d_haystack);
    cudaFree(d_addr_found);

    free(ciphertext_bytes);
    free(aad_bytes);

    if (h_addr_found != k_addr_not_found && h_addr_found + secret_len <= haystack_length) {
        print_tls13_app_traffic_secret_0(haystack + h_addr_found, secret_len, client_random, client, h_addr_found);
    } else {
        printf("No TLS 1.3 application traffic secret 0 found in haystack.\n");
    }

    return h_addr_found;
}

__host__ unsigned long long tls_app_traffic_secret_0_gcm_128_sha_256_scan(const unsigned char* haystack, const uint64_t haystack_length,
                                                                   unsigned char* app_data_record, int app_data_record_length,
                                                                   uint64_t seq_num, unsigned char client_random[32],
                                                                   const float entropyThreshold, const bool client) {

    printf("initiating TLS 1.3 %s_application_traffic_secret_0 scan (GCM 128, SHA 256) on %lu MB haystack with entropy threshold %f\n",
        client ? "client" : "server", haystack_length / (1000*1000), entropyThreshold);

    return tls13_app_traffic_secret_0_helper(haystack, haystack_length, app_data_record, app_data_record_length,
        seq_num, client_random, entropyThreshold, client, TLS13_APP_TRAFFIC_SECRET_0_LEN_SHA256,
        tls13_app_traffic_secret_0_scan_gcm128_sha256_kernel);
}

__host__ unsigned long long tls_app_traffic_secret_0_gcm_256_sha_384_scan(const unsigned char* haystack, const uint64_t haystack_length,
                                                                   unsigned char* app_data_record, int app_data_record_length,
                                                                   uint64_t seq_num, unsigned char client_random[32],
                                                                   const float entropyThreshold, const bool client) {

    printf("initiating TLS 1.3 %s_application_traffic_secret_0 scan (GCM 256, SHA 384) on %lu MB haystack with entropy threshold %f\n",
        client ? "client" : "server", haystack_length / (1000*1000), entropyThreshold);

    return tls13_app_traffic_secret_0_helper(haystack, haystack_length, app_data_record, app_data_record_length,
        seq_num, client_random, entropyThreshold, client, TLS13_APP_TRAFFIC_SECRET_0_LEN_SHA384,
        tls13_app_traffic_secret_0_scan_gcm256_sha384_kernel);
}
