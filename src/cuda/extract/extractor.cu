#include "extractor.h"
#include "tls-gcm-extract.h"
#include "../cuda_util.h"
#include <iostream>
#include <cuda_runtime.h>
#include <cmath>
#include <cstdint>
#include <math.h>

#define TLS_MASTER_SECRET_LEN 48
#define ENTROPY_SCAN_CANDIDATES_PER_THREAD 1
// assume haystack memory to be aligned in sections of 4 bytes
#define MEMORY_ALIGNMENT 4

#define CUDA_CHECK(err, msg)            \
    do {                                       \
        if ((err) != cudaSuccess) {            \
            printf("%s: %s\n", msg, cudaGetErrorString(err));  \
            return false;                      \
        }                                      \
    } while (0)

// Device function to calculate entropy for a given byte array.
__device__ float calculateEntropy(const unsigned char* data, int len) {
    // Create a local histogram for 256 possible byte values.
    float hist[256] = {0.0f};

    // Count the frequency of each byte in the data array.
    for (int i = 0; i < len; ++i) {
        hist[data[i]] += 1.0f;
    }

    // Calculate the entropy using the formula: -sum(p * log2(p)).
    float entropy = 0.0f;
    for (int i = 0; i < 256; ++i) {
        if (hist[i] > 0.0f) {
            float p = hist[i] / len;
            entropy -= p * log2f(p);
        }
    }
    return entropy;
}

__device__ void print_found_secret(unsigned char secret[TLS_MASTER_SECRET_LEN], unsigned char d_client_random[32], unsigned long long location) {
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

__global__ void tls_master_secret_scan_gcm128_sha256_kernel(const unsigned char* d_haystack, const uint64_t haystack_length,
                                                            const char percentile, unsigned char d_client_random[32],
                                                            unsigned char d_server_random[32], uint64_t seq_num,
                                                            unsigned char* d_aad, short aad_length, unsigned char* d_chiphertext,
                                                            short ciphertext_length, const float entropyThreshold, unsigned long long* d_addr_found) {

    const unsigned long thread_index = blockIdx.x * blockDim.x + threadIdx.x;
    const uint64_t percentile_index = (percentile * blockDim.x * gridDim.x + thread_index) * MEMORY_ALIGNMENT;

    if (percentile_index + 1 + TLS_MASTER_SECRET_LEN > haystack_length) {
        return;
    }

    unsigned char candidate[TLS_MASTER_SECRET_LEN];
    cuda_array_copy(candidate, d_haystack + percentile_index, TLS_MASTER_SECRET_LEN);
    float entropy = calculateEntropy(candidate, TLS_MASTER_SECRET_LEN);

    if (entropy < entropyThreshold) {
        // entropy not sufficiently high, free ressources
        return;
    }
    // entropy checks out
    
    // client finished plaintext start
    const char finished_plain_length = 4;
    unsigned char finished_plain[] = {0x14, 0x00, 0x00, 0x0c};

    bool isMatch = cuda_match_master_secret_gcm128_sha256_plaintxt_cmp(candidate, TLS_MASTER_SECRET_LEN, d_client_random, d_server_random, seq_num, finished_plain, finished_plain_length, d_chiphertext, ciphertext_length);
    //bool isMatch = cuda_match_master_secret_gcm128_sha256(candidate, TLS_MASTER_SECRET_LEN, d_client_random, d_server_random, seq_num, d_aad, aad_length, d_chiphertext, ciphertext_length);
    if (isMatch) {
        printf("\nMatch has entropy %f\n", entropy);
        print_found_secret(candidate, d_client_random, percentile_index);
        *d_addr_found = percentile_index;
    }
}

__global__ void tls_master_secret_scan_gcm256_sha384_kernel(const unsigned char* d_haystack, const uint64_t haystack_length,
                                                            const char percentile, unsigned char d_client_random[32],
                                                            unsigned char d_server_random[32], uint64_t seq_num,
                                                            unsigned char* d_aad, short aad_length, unsigned char* d_chiphertext,
                                                            short ciphertext_length, const float entropyThreshold, unsigned long long* d_addr_found) {

    const unsigned long thread_index = blockIdx.x * blockDim.x + threadIdx.x;
    const uint64_t percentile_index = (percentile * blockDim.x * gridDim.x + thread_index) * MEMORY_ALIGNMENT;

    if (percentile_index + 1 + TLS_MASTER_SECRET_LEN > haystack_length) {
        return;
    }

    unsigned char candidate[TLS_MASTER_SECRET_LEN];
    cuda_array_copy(candidate, d_haystack + percentile_index, TLS_MASTER_SECRET_LEN);
    float entropy = calculateEntropy(candidate, TLS_MASTER_SECRET_LEN);

    if (entropy < entropyThreshold) {
        // entropy not sufficiently high, free ressources
        return;
    }
    // entropy checks out

    // client finished plaintext start
    const char finished_plain_length = 6;
    unsigned char finished_plain[] = {0x14, 0x00, 0x00, 0x0c, 0x00, 0x02};
    
    bool isMatch = cuda_match_master_secret_gcm256_sha384_plaintxt_cmp(candidate, TLS_MASTER_SECRET_LEN, d_client_random, d_server_random, seq_num, finished_plain, finished_plain_length, d_chiphertext, ciphertext_length);
    if (isMatch) {
        printf("\nMatch has entropy %f\n", entropy);
        print_found_secret(candidate, d_client_random, percentile_index);
        *d_addr_found = percentile_index;
    }
}

__global__ void entropy_scan_kernel(const char* d_haystack, const uint64_t haystack_length, const long needle_length, const char percentile, unsigned long long* candidates, const float entropyThreshold) {

    const unsigned long thread_index = blockIdx.x * blockDim.x + threadIdx.x;
    const uint64_t percentile_index = percentile * blockDim.x * gridDim.x * ENTROPY_SCAN_CANDIDATES_PER_THREAD + thread_index * ENTROPY_SCAN_CANDIDATES_PER_THREAD;

    if (percentile_index + ENTROPY_SCAN_CANDIDATES_PER_THREAD + TLS_MASTER_SECRET_LEN > haystack_length) {
        return;
    }

 
    unsigned long long local_candidates[2];
    unsigned char entropyInput[512];
    local_candidates[0] = 0;
    local_candidates[1] = 0;

    for (unsigned int offset = 0; offset < ENTROPY_SCAN_CANDIDATES_PER_THREAD; offset++) {

        uint64_t position = percentile_index + offset;

        // copy entropy iunput
        for (int entropy_index = 0; entropy_index < needle_length; entropy_index++) {
            entropyInput[entropy_index] = d_haystack[position + entropy_index];
        }

        float entropy = calculateEntropy(entropyInput, needle_length);
        local_candidates[entropy > entropyThreshold]++;
    }

    atomicAdd(candidates, local_candidates[1]);
}


__host__ unsigned long long entropy_scan(const unsigned char* haystack, const uint64_t haystack_length, const uint64_t needle_length, const float entropyThreshold) {
    char *d_haystack = nullptr;
    unsigned long long *d_entropy_candidates = nullptr;

    printf("initiating entropy scan on %lld MB haystack with threshold %f\n", haystack_length / (1000*1000), entropyThreshold);

    // Allocate device memory for haystack
    cudaError_t err = cudaMalloc((void**)&d_haystack, haystack_length * sizeof(char));
    CUDA_CHECK(err, "cudaMalloc failed for d_haystack");
    
    // Allocate device memory for d_entropy_candidates
    err = cudaMalloc((void**)&d_entropy_candidates, sizeof(unsigned long long));
    CUDA_CHECK(err, "cudaMalloc failed for d_entropy_candidates");

    // Copy the haystack from host to device
    err = cudaMemcpy(d_haystack, haystack, haystack_length * sizeof(char), cudaMemcpyHostToDevice);
    CUDA_CHECK(err, "cudaMemcpy failed for d_haystack");

    // Set d_entropy_candidates to 0
    err = cudaMemset(d_entropy_candidates, 0, sizeof(unsigned long long));
    CUDA_CHECK(err, "cudaMemset failed for d_entropy_candidates");

    // Define optimal block and grid dimensions using occupancy calculator
    int min_grid_size = 0, block_size = 0;
    cudaOccupancyMaxPotentialBlockSize(&min_grid_size, &block_size, entropy_scan_kernel, 0, 0);

    // Ensure block size does not exceed device capability
    int max_threads_per_block;
    cudaDeviceGetAttribute(&max_threads_per_block, cudaDevAttrMaxThreadsPerBlock, 0);
    block_size = min(block_size, max_threads_per_block);

    // Define block and grid dimensions
    const int THREADS_PER_BLOCK = 1024;
    int total_threads = (haystack_length + ENTROPY_SCAN_CANDIDATES_PER_THREAD - 1) / (ENTROPY_SCAN_CANDIDATES_PER_THREAD * 100);
    int num_blocks = (total_threads + THREADS_PER_BLOCK - 1) / THREADS_PER_BLOCK;

    dim3 dim_threads(1024, 0);

    cudaEvent_t start, stop;
    float milliseconds = 0;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start);

    // Launch the CUDA kernel
    for (int i = 0; i < 100; i++) {
        entropy_scan_kernel<<<num_blocks, THREADS_PER_BLOCK>>>(d_haystack, haystack_length, needle_length, i, d_entropy_candidates, entropyThreshold);
        printf("\rentropy scan %d%%", i);
        cudaDeviceSynchronize();
        err = cudaGetLastError();
        if (err != cudaSuccess) printf("Kernel launch error: %s\n", cudaGetErrorString(err));
    }

    // Record stop time
    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&milliseconds, start, stop);
    printf("\nentropy scan runtime %.3f ms\n", milliseconds);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);

    // Check for launch errors
    err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("ERROR Kernel launch error: %s\n", cudaGetErrorString(err));
    }

    unsigned long long h_entropy_candidates;
    err = cudaMemcpy(&h_entropy_candidates, d_entropy_candidates, sizeof(unsigned long long), cudaMemcpyDeviceToHost);
    if (err != cudaSuccess) {
        fprintf(stderr, "ERRO Error copying d_entropy_candidates from device to host: %s\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    // Free the allocated device memory
    cudaFree(d_haystack);
    cudaFree(d_entropy_candidates);

    return h_entropy_candidates;
}

__host__ unsigned long long tls_master_secret_helper(const unsigned char* haystack, const uint64_t haystack_length,
                                                    unsigned char client_random[32], unsigned char server_random[32],
                                                    unsigned char* client_finished_msg, int client_finished_length,
                                                    const float entropyThreshold, 
                                                    void (*search_kernel) (const unsigned char*, const uint64_t,
                                                            const char, unsigned char[32],
                                                            unsigned char[32], uint64_t,
                                                            unsigned char*, short, unsigned char*,
                                                            short, const float, unsigned long long*)) {

    if (client_finished_msg[0] != 0x16) {
        printf("ERROR did not receive a finished message!\n");
        return 0;
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

        // first 8 bytes: record and sequence number
        memcpy(aad_bytes, &target_seq_num, 8);
        aad_bytes[ 8] = client_finished_msg[0]; // type
        aad_bytes[ 9] = client_finished_msg[1]; // version
        aad_bytes[10] = client_finished_msg[2]; // version
        aad_bytes[11] = 0x00; // encode encrypted length (for dtls 1.2)
        aad_bytes[12] = 0x18; // encode encrypted length (for dtls 1.2)
    } else {
        memcpy(&target_seq_num, client_finished_msg + 5, 8);

        memcpy(aad_bytes, &target_seq_num, 8);
        aad_bytes[ 8] = client_finished_msg[0]; // type
        aad_bytes[ 9] = client_finished_msg[1]; // version
        aad_bytes[10] = client_finished_msg[2]; // version
        aad_bytes[11] = 0x00; // encode encrypted length (for tls 1.2)
        aad_bytes[12] = 0x10; // encode encrypted length (for tls 1.2)
    }
    
    // extract cipher text
    const int ciphertext_len = client_finished_length - AAD_LENGTH - (dtls ? 8 : 0);
    unsigned char* ciphertext_bytes = (unsigned char*) malloc(ciphertext_len);
    memcpy(ciphertext_bytes, client_finished_msg + AAD_LENGTH + (dtls ? 8 : 0), ciphertext_len);

    unsigned long long h_addr_found = 0;

    unsigned char *d_haystack = nullptr;
    unsigned char* d_client_random = nullptr;
    unsigned char* d_server_random = nullptr;
    unsigned char* d_aad = nullptr;
    unsigned char* d_chiphertext = nullptr;
    unsigned long long* d_addr_found = nullptr;

    // Allocate device memory
    cudaError_t err;
    err = cudaMalloc((void**)&d_haystack, haystack_length);
    CUDA_CHECK(err, "cudaMalloc failed for d_haystack");
    err = cudaMalloc((void**)&d_client_random, 32);
    CUDA_CHECK(err, "cudaMalloc failed for d_client_random");
    err = cudaMalloc((void**)&d_server_random, 32);
    CUDA_CHECK(err, "cudaMalloc failed for d_server_random");
    err = cudaMalloc((void**)&d_aad, AAD_LENGTH);
    CUDA_CHECK(err, "cudaMalloc failed for d_aad");
    err = cudaMalloc((void**)&d_chiphertext, ciphertext_len);
    CUDA_CHECK(err, "cudaMalloc failed for d_chiphertext");
    err = cudaMalloc((void**)&d_addr_found, sizeof(unsigned long long));
    CUDA_CHECK(err, "cudaMalloc failed for d_addr_found");
    
    err = cudaMemcpy(d_haystack, haystack, haystack_length, cudaMemcpyHostToDevice);
    CUDA_CHECK(err, "cudaMemcpy failed for d_haystack");
    err = cudaMemcpy(d_client_random, client_random, 32 * sizeof(unsigned char), cudaMemcpyHostToDevice);
    CUDA_CHECK(err, "cudaMemcpy failed for d_client_random");
    err = cudaMemcpy(d_server_random, server_random, 32 * sizeof(unsigned char), cudaMemcpyHostToDevice);
    CUDA_CHECK(err, "cudaMemcpy failed for d_server_random");
    err = cudaMemcpy(d_aad, aad_bytes, AAD_LENGTH * sizeof(unsigned char), cudaMemcpyHostToDevice);
    CUDA_CHECK(err, "cudaMemcpy failed for d_aad");
    err = cudaMemcpy(d_chiphertext, ciphertext_bytes, ciphertext_len * sizeof(unsigned char), cudaMemcpyHostToDevice);
    CUDA_CHECK(err, "cudaMemcpy failed for d_chiphertext");

    err = cudaMemset(d_addr_found, 0x00, sizeof(unsigned long long));
    CUDA_CHECK(err, "cudaMemset failed for d_addr_found");

    
    cudaFuncAttributes attr;
    cudaFuncGetAttributes(&attr, search_kernel);

    // Define optimal block and grid dimensions using occupancy calculator
    int min_grid_size = 0, block_size = 0;
    cudaOccupancyMaxPotentialBlockSize(&min_grid_size, &block_size, search_kernel, 0, 0);

    // Ensure block size does not exceed device capability
    int max_threads_per_block = attr.maxThreadsPerBlock;

    // Define block and grid dimensions
    uint64_t candidates_per_percentile = haystack_length / (100 * MEMORY_ALIGNMENT);
    long num_blocks = (candidates_per_percentile + max_threads_per_block - 1) / max_threads_per_block;

    printf("#### launch parameters: min gid: %d, min block %d, max threads %d, num blocks: %d, num threads: %d\n",
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

    // Launch the CUDA kernel
    printf("\rmaster secret scan 0%%");
    for (int i = 0; i < 100; i++) {
        search_kernel<<<num_blocks, max_threads_per_block>>>(d_haystack, haystack_length, i,
            d_client_random, d_server_random, target_seq_num, d_aad, AAD_LENGTH, d_chiphertext, ciphertext_len, entropyThreshold, d_addr_found);
        printf("\rmaster secret scan %d%%", i);
        cudaDeviceSynchronize();
        err = cudaGetLastError();
        if (err != cudaSuccess) printf("Kernel launch error: %s\n", cudaGetErrorString(err));

        // check if secret found already
        err = cudaMemcpy(&h_addr_found, d_addr_found, sizeof(unsigned long long), cudaMemcpyDeviceToHost);
        CUDA_CHECK(err, "cudaMemcpy failed for d_addr_found to host");
        if (h_addr_found != 0) break;
    }

    // Record stop time
    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&milliseconds, start, stop);
    printf("\nscan runtime %.3f ms\n", milliseconds);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);

    // Check for launch errors
    err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("ERROR Kernel launch error: %s\n", cudaGetErrorString(err));
    }

    // Free the allocated device memory
    cudaFree(d_haystack);
    cudaFree(d_client_random);
    cudaFree(d_server_random);
    cudaFree(d_aad);
    cudaFree(d_chiphertext);
    cudaFree(d_addr_found);

    free(ciphertext_bytes);
    free(aad_bytes);
}


__host__ unsigned long long tls_master_secret_gcm_128_sha_256_scan(const unsigned char* haystack, const uint64_t haystack_length,
                                                                   unsigned char client_random[32], unsigned char server_random[32],
                                                                   unsigned char* client_finished_msg, int client_finished_length,
                                                                   const float entropyThreshold) {

    printf("initiating master secret scan (GCM 128, SHA 256) on %lld MB haystack with entropy threshold %f\n", haystack_length / (1000*1000), entropyThreshold);

    return tls_master_secret_helper(haystack, haystack_length, client_random, server_random, client_finished_msg, client_finished_length, entropyThreshold, tls_master_secret_scan_gcm128_sha256_kernel);
}

__host__ unsigned long long tls_master_secret_gcm_256_sha_384_scan(const unsigned char* haystack, const uint64_t haystack_length,
                                                                   unsigned char client_random[32], unsigned char server_random[32],
                                                                   unsigned char* client_finished_msg, int client_finished_length,
                                                                   const float entropyThreshold) {

    printf("initiating master secret scan (GCM 256, SHA 384) on %lld MB haystack with entropy threshold %f\n", haystack_length / (1000*1000), entropyThreshold);

    return tls_master_secret_helper(haystack, haystack_length, client_random, server_random, client_finished_msg, client_finished_length, entropyThreshold, tls_master_secret_scan_gcm256_sha384_kernel);
}

