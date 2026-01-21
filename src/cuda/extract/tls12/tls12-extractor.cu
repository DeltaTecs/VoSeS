#include "tls12-extractor.h"
#include "tls12-gcm-extract.h"
#include "../common/extractor-common.h"
#include "../../cuda_util.h"
#include <cuda_runtime.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#define TLS_MASTER_SECRET_LEN 48
#define TLS12_AAD_LENGTH 13
#define TLS12_MAX_CIPHERTEXT_LEN 16384

__device__ __constant__ unsigned char d_tls12_const_aad[TLS12_AAD_LENGTH];
__device__ __constant__ unsigned char d_tls12_const_ciphertext[TLS12_MAX_CIPHERTEXT_LEN];
__device__ __constant__ short d_tls12_const_ciphertext_length;

#define CUDA_CHECK(err, msg)            \
    do {                                \
        if ((err) != cudaSuccess) {     \
            printf("%s: %s\n", msg, cudaGetErrorString(err));  \
            return false;               \
        }                               \
    } while (0)

__device__ void print_found_secret(unsigned char secret[TLS_MASTER_SECRET_LEN],
                                   unsigned char d_client_random[32],
                                   unsigned long long location) {
    printf("\r*** -----------------------------------\n");
        printf("*** Master Secret match found at data index %lld\n", location);
        printf("*** Hex value ");
        for (char i = 0; i < TLS_MASTER_SECRET_LEN; i++) {
            printf("%02X", secret[i]);
        }
        printf("\n");
        printf("*** Use the following line for your Wireshark master secret log file to decrypt the session of the given finished message and randoms:\n");
        printf("CLIENT_RANDOM ");
        for (char i = 0; i < 32; i++) {
            printf("%02x", d_client_random[i]);
        }
        printf(" ");
        for (char i = 0; i < TLS_MASTER_SECRET_LEN; i++) {
            printf("%02x", secret[i]);
        }
        printf("\n");
        printf("*** -----------------------------------\n\n");
}

__global__ void tls12_master_secret_scan_gcm128_sha256_kernel(const unsigned char* d_haystack, const uint64_t haystack_length,
                                                            const char percentile, unsigned char d_client_random[32],
                                                            unsigned char d_server_random[32], uint64_t seq_num,
                                                            const float entropyThreshold, unsigned long long* d_addr_found) {

    const unsigned long thread_index = blockIdx.x * blockDim.x + threadIdx.x;
    const uint64_t percentile_index = (percentile * blockDim.x * gridDim.x + thread_index) * d_memory_alignment;

    if (percentile_index + 1 + TLS_MASTER_SECRET_LEN > haystack_length) {
        return;
    }

    unsigned char candidate[TLS_MASTER_SECRET_LEN];
    cuda_array_copy(candidate, d_haystack + percentile_index, TLS_MASTER_SECRET_LEN);
    float entropy = calculateEntropy(candidate, TLS_MASTER_SECRET_LEN);

    if (entropy < entropyThreshold) {
        return;
    }

    const char finished_plain_length = 4;
    unsigned char finished_plain[] = {0x14, 0x00, 0x00, 0x0c};

    bool isMatch = cuda_match_master_secret_gcm128_sha256_plaintxt_cmp(candidate, TLS_MASTER_SECRET_LEN,
                                                                       d_client_random, d_server_random, seq_num,
                                                                       finished_plain, finished_plain_length,
                                                                       d_tls12_const_ciphertext, d_tls12_const_ciphertext_length);
    if (isMatch) {
        printf("\nMatch has entropy %f\n", entropy);
        print_found_secret(candidate, d_client_random, percentile_index);
        *d_addr_found = percentile_index;
    }
}

__global__ void tls12_master_secret_scan_gcm256_sha384_kernel(const unsigned char* d_haystack, const uint64_t haystack_length,
                                                            const char percentile, unsigned char d_client_random[32],
                                                            unsigned char d_server_random[32], uint64_t seq_num,
                                                            const float entropyThreshold, unsigned long long* d_addr_found) {

    const unsigned long thread_index = blockIdx.x * blockDim.x + threadIdx.x;
    const uint64_t percentile_index = (percentile * blockDim.x * gridDim.x + thread_index) * d_memory_alignment;

    if (percentile_index + 1 + TLS_MASTER_SECRET_LEN > haystack_length) {
        return;
    }

    unsigned char candidate[TLS_MASTER_SECRET_LEN];
    cuda_array_copy(candidate, d_haystack + percentile_index, TLS_MASTER_SECRET_LEN);
    float entropy = calculateEntropy(candidate, TLS_MASTER_SECRET_LEN);

    if (entropy < entropyThreshold) {
        return;
    }

    const char finished_plain_length = 4;
    unsigned char finished_plain[] = {0x14, 0x00, 0x00, 0x0c};
    
    bool isMatch = cuda_match_master_secret_gcm256_sha384_plaintxt_cmp(candidate, TLS_MASTER_SECRET_LEN,
                                                                       d_client_random, d_server_random, seq_num,
                                                                       finished_plain, finished_plain_length,
                                                                       d_tls12_const_ciphertext, d_tls12_const_ciphertext_length);
    if (isMatch) {
        printf("\nMatch has entropy %f\n", entropy);
        print_found_secret(candidate, d_client_random, percentile_index);
        *d_addr_found = percentile_index;
    }
}

__host__ unsigned long long tls12_master_secret_helper(const unsigned char* haystack, const uint64_t haystack_length,
                                                    unsigned char client_random[32], unsigned char server_random[32],
                                                    unsigned char* client_finished_msg, int client_finished_length,
                                                    const float entropyThreshold, 
                                                    void (*search_kernel) (const unsigned char*, const uint64_t,
                                                            const char, unsigned char[32],
                                                            unsigned char[32], uint64_t,
                                                            const float, unsigned long long*)) {

    if (client_finished_msg[0] != 0x16) {
        printf("ERROR did not receive a finished message!\n");
        return k_addr_not_found;
    }

    bool dtls = client_finished_msg[1] == 0xFE && client_finished_msg[2] == 0xFD;
    if (dtls) {
        printf("DTLS detected.\n");
    }

    const short AAD_LENGTH = 13;
    unsigned char* aad_bytes = (unsigned char*) malloc(AAD_LENGTH);
    uint64_t target_seq_num;
    if (dtls) {
        memcpy(&target_seq_num, client_finished_msg + 3, 8);

        memcpy(aad_bytes, &target_seq_num, 8);
        aad_bytes[ 8] = client_finished_msg[0];
        aad_bytes[ 9] = client_finished_msg[1];
        aad_bytes[10] = client_finished_msg[2];
        aad_bytes[11] = 0x00;
        aad_bytes[12] = 0x18;
    } else {
        memcpy(&target_seq_num, client_finished_msg + 5, 8);

        memcpy(aad_bytes, &target_seq_num, 8);
        aad_bytes[ 8] = client_finished_msg[0];
        aad_bytes[ 9] = client_finished_msg[1];
        aad_bytes[10] = client_finished_msg[2];
        aad_bytes[11] = 0x00;
        aad_bytes[12] = 0x10;
    }
    
    const int ciphertext_len = client_finished_length - AAD_LENGTH - (dtls ? 8 : 0);
    if (ciphertext_len > TLS12_MAX_CIPHERTEXT_LEN) {
        printf("ERROR ciphertext length %d exceeds constant memory limit %d.\n", ciphertext_len, TLS12_MAX_CIPHERTEXT_LEN);
        free(aad_bytes);
        return k_addr_not_found;
    }
    unsigned char* ciphertext_bytes = (unsigned char*) malloc(ciphertext_len);
    memcpy(ciphertext_bytes, client_finished_msg + AAD_LENGTH + (dtls ? 8 : 0), ciphertext_len);

    unsigned long long h_addr_found = k_addr_not_found;

    unsigned char *d_haystack = nullptr;
    unsigned char* d_client_random = nullptr;
    unsigned char* d_server_random = nullptr;
    unsigned long long* d_addr_found = nullptr;

    cudaError_t err;
    err = cudaMalloc((void**)&d_haystack, haystack_length);
    CUDA_CHECK(err, "cudaMalloc failed for d_haystack");
    err = cudaMalloc((void**)&d_client_random, 32);
    CUDA_CHECK(err, "cudaMalloc failed for d_client_random");
    err = cudaMalloc((void**)&d_server_random, 32);
    CUDA_CHECK(err, "cudaMalloc failed for d_server_random");
    err = cudaMalloc((void**)&d_addr_found, sizeof(unsigned long long));
    CUDA_CHECK(err, "cudaMalloc failed for d_addr_found");
    
    err = cudaMemcpy(d_haystack, haystack, haystack_length, cudaMemcpyHostToDevice);
    CUDA_CHECK(err, "cudaMemcpy failed for d_haystack");
    err = cudaMemcpy(d_client_random, client_random, 32 * sizeof(unsigned char), cudaMemcpyHostToDevice);
    CUDA_CHECK(err, "cudaMemcpy failed for d_client_random");
    err = cudaMemcpy(d_server_random, server_random, 32 * sizeof(unsigned char), cudaMemcpyHostToDevice);
    CUDA_CHECK(err, "cudaMemcpy failed for d_server_random");

    // Copy AAD and ciphertext to constant memory
    err = cudaMemcpyToSymbol(d_tls12_const_aad, aad_bytes, AAD_LENGTH * sizeof(unsigned char));
    CUDA_CHECK(err, "cudaMemcpyToSymbol failed for d_tls12_const_aad");
    err = cudaMemcpyToSymbol(d_tls12_const_ciphertext, ciphertext_bytes, ciphertext_len * sizeof(unsigned char));
    CUDA_CHECK(err, "cudaMemcpyToSymbol failed for d_tls12_const_ciphertext");
    short h_ciphertext_len = (short)ciphertext_len;
    err = cudaMemcpyToSymbol(d_tls12_const_ciphertext_length, &h_ciphertext_len, sizeof(short));
    CUDA_CHECK(err, "cudaMemcpyToSymbol failed for d_tls12_const_ciphertext_length");

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

    printf("\rmaster secret scan 0%%");
    for (int i = 0; i < 100; i++) {
        search_kernel<<<num_blocks, max_threads_per_block>>>(d_haystack, haystack_length, i,
            d_client_random, d_server_random, target_seq_num,
            entropyThreshold, d_addr_found);
        printf("\rmaster secret scan %d%%", i);
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
    cudaFree(d_client_random);
    cudaFree(d_server_random);
    cudaFree(d_addr_found);

    free(ciphertext_bytes);
    free(aad_bytes);

    return h_addr_found;
}

__host__ unsigned long long tls12_master_secret_gcm_128_sha_256_scan(const unsigned char* haystack, const uint64_t haystack_length,
                                                                   unsigned char client_random[32], unsigned char server_random[32],
                                                                   unsigned char* client_finished_msg, int client_finished_length,
                                                                   const float entropyThreshold) {

    printf("initiating TLS 1.2 master secret scan (GCM 128, SHA 256) on %lu MB haystack with entropy threshold %f\n",
           haystack_length / (1000*1000), entropyThreshold);

    return tls12_master_secret_helper(haystack, haystack_length, client_random, server_random,
                                      client_finished_msg, client_finished_length,
                                      entropyThreshold, tls12_master_secret_scan_gcm128_sha256_kernel);
}

__host__ unsigned long long tls12_master_secret_gcm_256_sha_384_scan(const unsigned char* haystack, const uint64_t haystack_length,
                                                                   unsigned char client_random[32], unsigned char server_random[32],
                                                                   unsigned char* client_finished_msg, int client_finished_length,
                                                                   const float entropyThreshold) {

    printf("initiating TLS 1.2 master secret scan (GCM 256, SHA 384) on %lu MB haystack with entropy threshold %f\n",
           haystack_length / (1000*1000), entropyThreshold);

    return tls12_master_secret_helper(haystack, haystack_length, client_random, server_random,
                                      client_finished_msg, client_finished_length,
                                      entropyThreshold, tls12_master_secret_scan_gcm256_sha384_kernel);
}
