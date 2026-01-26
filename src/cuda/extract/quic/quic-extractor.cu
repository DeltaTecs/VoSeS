#include "quic-extractor.h"
#include "quic-gcm-extract.h"
#include "../common/extractor-common.h"
#include "../../cuda_util.h"
#include <cuda_runtime.h>
#include <math.h>
#include <stdio.h>

#define QUIC_APP_TRAFFIC_SECRET_0_LEN_SHA256 32
#define QUIC_APP_TRAFFIC_SECRET_0_LEN_SHA384 48
#define QUIC_MAX_PACKET_LEN 16384

__device__ __constant__ unsigned char d_const_packet[QUIC_MAX_PACKET_LEN];
__device__ __constant__ short d_const_packet_length;
__device__ __constant__ short d_const_pn_offset;

#define CUDA_CHECK(err, msg)            \
    do {                                \
        if ((err) != cudaSuccess) {     \
            printf("%s: %s\n", msg, cudaGetErrorString(err));  \
            return false;               \
        }                               \
    } while (0)

__global__ void quic_app_traffic_secret_0_scan_gcm128_sha256_kernel(const unsigned char* d_haystack, const uint64_t haystack_length,
                                                            const char percentile,
                                                            const float entropyThreshold, unsigned long long* d_addr_found) {

    const unsigned long thread_index = blockIdx.x * blockDim.x + threadIdx.x;
    const uint64_t percentile_index = (percentile * blockDim.x * gridDim.x + thread_index) * d_memory_alignment;

    if (percentile_index + 1 + QUIC_APP_TRAFFIC_SECRET_0_LEN_SHA256 > haystack_length) {
        return;
    }

    unsigned char candidate[QUIC_APP_TRAFFIC_SECRET_0_LEN_SHA256];
    cuda_array_copy(candidate, d_haystack + percentile_index, QUIC_APP_TRAFFIC_SECRET_0_LEN_SHA256);
    float entropy = calculateEntropy(candidate, QUIC_APP_TRAFFIC_SECRET_0_LEN_SHA256);

    if (entropy < entropyThreshold) {
        return;
    }

    bool isMatch = cuda_match_quic_app_traffic_secret_0_gcm128_sha256(candidate, QUIC_APP_TRAFFIC_SECRET_0_LEN_SHA256,
                                                                      d_const_packet, d_const_packet_length, d_const_pn_offset);
    if (isMatch) {
        printf("\nMatch has entropy %f\n", entropy);
        *d_addr_found = percentile_index;
    }
}

__global__ void quic_app_traffic_secret_0_scan_gcm256_sha384_kernel(const unsigned char* d_haystack, const uint64_t haystack_length,
                                                            const char percentile,
                                                            const float entropyThreshold, unsigned long long* d_addr_found) {

    const unsigned long thread_index = blockIdx.x * blockDim.x + threadIdx.x;
    const uint64_t percentile_index = (percentile * blockDim.x * gridDim.x + thread_index) * d_memory_alignment;

    if (percentile_index + 1 + QUIC_APP_TRAFFIC_SECRET_0_LEN_SHA384 > haystack_length) {
        return;
    }

    unsigned char candidate[QUIC_APP_TRAFFIC_SECRET_0_LEN_SHA384];
    cuda_array_copy(candidate, d_haystack + percentile_index, QUIC_APP_TRAFFIC_SECRET_0_LEN_SHA384);
    float entropy = calculateEntropy(candidate, QUIC_APP_TRAFFIC_SECRET_0_LEN_SHA384);

    if (entropy < entropyThreshold) {
        return;
    }

    bool isMatch = cuda_match_quic_app_traffic_secret_0_gcm256_sha384(candidate, QUIC_APP_TRAFFIC_SECRET_0_LEN_SHA384,
                                                                      d_const_packet, d_const_packet_length, d_const_pn_offset);
    if (isMatch) {
        printf("\nMatch has entropy %f\n", entropy);
        *d_addr_found = percentile_index;
    }
}

__host__ unsigned long long quic_app_traffic_secret_0_helper(const unsigned char* haystack, const uint64_t haystack_length,
                                                             unsigned char* packet, int packet_length,
                                                             short pn_offset, unsigned char client_random[32],
                                                             const float entropyThreshold, const bool client,
                                                             const int secret_len,
                                                             void (*search_kernel) (const unsigned char*, const uint64_t,
                                                                     const char,
                                                                     const float, unsigned long long*)) {

    if (packet_length <= 0) {
        printf("ERROR QUIC packet is empty.\n");
        return k_addr_not_found;
    }
    if (pn_offset < 0 || pn_offset >= packet_length) {
        printf("ERROR QUIC pn_offset %d is out of bounds for packet length %d.\n", pn_offset, packet_length);
        return k_addr_not_found;
    }
    if (packet_length > QUIC_MAX_PACKET_LEN) {
        printf("ERROR QUIC packet length %d exceeds constant memory limit %d.\n", packet_length, QUIC_MAX_PACKET_LEN);
        return k_addr_not_found;
    }

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

    // Copy packet data to constant memory
    err = cudaMemcpyToSymbol(d_const_packet, packet, packet_length * sizeof(unsigned char));
    CUDA_CHECK(err, "cudaMemcpyToSymbol failed for d_const_packet");
    short h_packet_length = (short)packet_length;
    err = cudaMemcpyToSymbol(d_const_packet_length, &h_packet_length, sizeof(short));
    CUDA_CHECK(err, "cudaMemcpyToSymbol failed for d_const_packet_length");
    err = cudaMemcpyToSymbol(d_const_pn_offset, &pn_offset, sizeof(short));
    CUDA_CHECK(err, "cudaMemcpyToSymbol failed for d_const_pn_offset");

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
            entropyThreshold, d_addr_found);
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

    if (h_addr_found != k_addr_not_found && h_addr_found + secret_len <= haystack_length) {
        print_tls13_app_traffic_secret_0(haystack + h_addr_found, secret_len, client_random, client, h_addr_found);
    } else {
        printf("No QUIC application traffic secret 0 found in haystack.\n");
    }

    return h_addr_found;
}

__host__ unsigned long long quic_app_traffic_secret_0_gcm_128_sha_256_scan(const unsigned char* haystack, const uint64_t haystack_length,
                                                                   unsigned char* packet, int packet_length,
                                                                   short pn_offset, unsigned char client_random[32],
                                                                   const float entropyThreshold, const bool client) {

    printf("initiating QUIC %s_application_traffic_secret_0 scan (GCM 128, SHA 256) on %lu MB haystack with entropy threshold %f\n",
        client ? "client" : "server", haystack_length / (1000*1000), entropyThreshold);

    return quic_app_traffic_secret_0_helper(haystack, haystack_length, packet, packet_length,
        pn_offset, client_random, entropyThreshold, client, QUIC_APP_TRAFFIC_SECRET_0_LEN_SHA256,
        quic_app_traffic_secret_0_scan_gcm128_sha256_kernel);
}

__host__ unsigned long long quic_app_traffic_secret_0_gcm_256_sha_384_scan(const unsigned char* haystack, const uint64_t haystack_length,
                                                                   unsigned char* packet, int packet_length,
                                                                   short pn_offset, unsigned char client_random[32],
                                                                   const float entropyThreshold, const bool client) {

    printf("initiating QUIC %s_application_traffic_secret_0 scan (GCM 256, SHA 384) on %lu MB haystack with entropy threshold %f\n",
        client ? "client" : "server", haystack_length / (1000*1000), entropyThreshold);

    return quic_app_traffic_secret_0_helper(haystack, haystack_length, packet, packet_length,
        pn_offset, client_random, entropyThreshold, client, QUIC_APP_TRAFFIC_SECRET_0_LEN_SHA384,
        quic_app_traffic_secret_0_scan_gcm256_sha384_kernel);
}
