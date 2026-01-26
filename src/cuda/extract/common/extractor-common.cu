#include "extractor-common.h"
#include <cuda_runtime.h>
#include <math.h>
#include <stdio.h>

#define ENTROPY_SCAN_CANDIDATES_PER_THREAD 1

__device__ __constant__ uint64_t d_memory_alignment = 4;
static uint64_t h_memory_alignment = 4;

__host__ uint64_t get_memory_alignment() {
    return h_memory_alignment;
}

__host__ bool set_memory_alignment(uint64_t alignment) {
    if (alignment == 0) {
        printf("ERROR memory alignment must be greater than zero\n");
        return false;
    }
    h_memory_alignment = alignment;
    cudaError_t err = cudaMemcpyToSymbol(d_memory_alignment, &alignment, sizeof(alignment));
    if (err != cudaSuccess) {
        printf("cudaMemcpyToSymbol failed for d_memory_alignment: %s\n", cudaGetErrorString(err));
        return false;
    }
    return true;
}

__global__ void entropy_scan_kernel(const char* d_haystack, const uint64_t haystack_length,
                                    const long needle_length, const char percentile,
                                    unsigned long long* candidates, const float entropyThreshold) {

    const unsigned long thread_index = blockIdx.x * blockDim.x + threadIdx.x;
    const uint64_t percentile_index = percentile * blockDim.x * gridDim.x *
                                      ENTROPY_SCAN_CANDIDATES_PER_THREAD +
                                      thread_index * ENTROPY_SCAN_CANDIDATES_PER_THREAD;

    if (percentile_index + ENTROPY_SCAN_CANDIDATES_PER_THREAD + needle_length > haystack_length) {
        return;
    }

    unsigned long long local_candidates[2];
    unsigned char entropyInput[512];
    local_candidates[0] = 0;
    local_candidates[1] = 0;

    for (unsigned int offset = 0; offset < ENTROPY_SCAN_CANDIDATES_PER_THREAD; offset++) {

        uint64_t position = percentile_index + offset;

        for (int entropy_index = 0; entropy_index < needle_length; entropy_index++) {
            entropyInput[entropy_index] = d_haystack[position + entropy_index];
        }

        float entropy = calculateEntropy(entropyInput, needle_length);
        local_candidates[entropy > entropyThreshold]++;
    }

    atomicAdd(candidates, local_candidates[1]);
}

__host__ unsigned long long entropy_scan(const unsigned char* haystack, const uint64_t haystack_length,
                                         const uint64_t needle_length, const float entropyThreshold) {
    char *d_haystack = nullptr;
    unsigned long long *d_entropy_candidates = nullptr;

    printf("initiating entropy scan on %lu MB haystack with threshold %f\n",
           haystack_length / (1000*1000), entropyThreshold);

    cudaError_t err = cudaMalloc((void**)&d_haystack, haystack_length * sizeof(char));
    if (err != cudaSuccess) {
        printf("cudaMalloc failed for d_haystack: %s\n", cudaGetErrorString(err));
        return false;
    }
    
    err = cudaMalloc((void**)&d_entropy_candidates, sizeof(unsigned long long));
    if (err != cudaSuccess) {
        printf("cudaMalloc failed for d_entropy_candidates: %s\n", cudaGetErrorString(err));
        cudaFree(d_haystack);
        return false;
    }

    err = cudaMemcpy(d_haystack, haystack, haystack_length * sizeof(char), cudaMemcpyHostToDevice);
    if (err != cudaSuccess) {
        printf("cudaMemcpy failed for d_haystack: %s\n", cudaGetErrorString(err));
        cudaFree(d_haystack);
        cudaFree(d_entropy_candidates);
        return false;
    }

    err = cudaMemset(d_entropy_candidates, 0, sizeof(unsigned long long));
    if (err != cudaSuccess) {
        printf("cudaMemset failed for d_entropy_candidates: %s\n", cudaGetErrorString(err));
        cudaFree(d_haystack);
        cudaFree(d_entropy_candidates);
        return false;
    }

    int min_grid_size = 0, block_size = 0;
    cudaOccupancyMaxPotentialBlockSize(&min_grid_size, &block_size, entropy_scan_kernel, 0, 0);

    int max_threads_per_block;
    cudaDeviceGetAttribute(&max_threads_per_block, cudaDevAttrMaxThreadsPerBlock, 0);
    block_size = min(block_size, max_threads_per_block);

    const int THREADS_PER_BLOCK = 1024;
    int total_threads = (haystack_length + ENTROPY_SCAN_CANDIDATES_PER_THREAD - 1) /
                        (ENTROPY_SCAN_CANDIDATES_PER_THREAD * 100);
    int num_blocks = (total_threads + THREADS_PER_BLOCK - 1) / THREADS_PER_BLOCK;

    cudaEvent_t start, stop;
    float milliseconds = 0;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start);

    for (int i = 0; i < 100; i++) {
        entropy_scan_kernel<<<num_blocks, THREADS_PER_BLOCK>>>(
            d_haystack, haystack_length, needle_length, i, d_entropy_candidates, entropyThreshold);
        printf("\rentropy scan %d%%", i);
        cudaDeviceSynchronize();
        err = cudaGetLastError();
        if (err != cudaSuccess) printf("Kernel launch error: %s\n", cudaGetErrorString(err));
    }

    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&milliseconds, start, stop);
    printf("\nentropy scan runtime %.3f ms\n", milliseconds);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);

    err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("ERROR Kernel launch error: %s\n", cudaGetErrorString(err));
    }

    unsigned long long h_entropy_candidates = 0;
    err = cudaMemcpy(&h_entropy_candidates, d_entropy_candidates,
                     sizeof(unsigned long long), cudaMemcpyDeviceToHost);
    if (err != cudaSuccess) {
        fprintf(stderr, "ERROR copying d_entropy_candidates from device to host: %s\n",
                cudaGetErrorString(err));
        cudaFree(d_haystack);
        cudaFree(d_entropy_candidates);
        return false;
    }

    cudaFree(d_haystack);
    cudaFree(d_entropy_candidates);

    return h_entropy_candidates;
}

void print_tls13_app_traffic_secret_0(const unsigned char* secret, int secret_len,
                                      const unsigned char client_random[32], bool client,
                                      unsigned long long location) {
    printf("\r*** -----------------------------------\n");
    printf("*** Application Traffic Secret 0 match found at data index %llu\n", location);
    printf("*** Hex value ");
    for (int i = 0; i < secret_len; i++) {
        printf("%02X", secret[i]);
    }
    printf("\n");
    printf("*** Use the following line for your Wireshark key log file to decrypt the session of the given client random:\n");
    printf("%s ", client ? "CLIENT_TRAFFIC_SECRET_0" : "SERVER_TRAFFIC_SECRET_0");
    for (int i = 0; i < 32; i++) {
        printf("%02x", client_random[i]);
    }
    printf(" ");
    for (int i = 0; i < secret_len; i++) {
        printf("%02x", secret[i]);
    }
    printf("\n");
    printf("*** -----------------------------------\n\n");
}
