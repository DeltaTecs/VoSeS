#include "extractor.h"

#include <iostream>
#include <cuda_runtime.h>
#include <cmath>
#include <cstdint>
#include <math.h>

#define CUDA_CHECK_MALLOC(err, msg)            \
    do {                                       \
        if ((err) != cudaSuccess) {            \
            printf("%s: %s\n", msg, cudaGetErrorString(err));  \
            return false;                      \
        }                                      \
    } while (0)


#define CUDA_CHECK_COPY(err, d_haystack, msg)  \
    do {                                            \
        if ((err) != cudaSuccess) {                 \
            printf("%s: %s\n", msg, cudaGetErrorString(err));  \
            cudaFree(d_haystack);                   \
            return false;                           \
        }                                           \
    } while (0)


#define BYTES_PER_THREAD 20


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


__global__ void entropy_scan_kernel(const char* d_haystack, const long haystack_length, const long needle_length, const char percentile, unsigned long long* candidates, const float entropyThreshold) {

    const unsigned long thread_index = blockIdx.x * blockDim.x + threadIdx.x;
    const uint64_t percentile_index = percentile * blockDim.x * gridDim.x * BYTES_PER_THREAD + thread_index * BYTES_PER_THREAD;

    if (percentile_index + BYTES_PER_THREAD + needle_length > haystack_length) {
        return;
    }

 
    unsigned long long local_candidates[2];
    unsigned char entropyInput[512];
    local_candidates[0] = 0;
    local_candidates[1] = 0;

    for (unsigned int offset = 0; offset < BYTES_PER_THREAD; offset++) {

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
    CUDA_CHECK_MALLOC(err, "cudaMalloc failed for d_haystack");
    
    // Allocate device memory for d_entropy_candidates
    err = cudaMalloc((void**)&d_entropy_candidates, sizeof(unsigned long long));
    CUDA_CHECK_MALLOC(err, "cudaMalloc failed for d_entropy_candidates");

    // Copy the haystack from host to device
    err = cudaMemcpy(d_haystack, haystack, haystack_length * sizeof(char), cudaMemcpyHostToDevice);
    CUDA_CHECK_COPY(err, d_haystack, "cudaMemcpy failed for d_haystack");

    // Set d_entropy_candidates to 0
    err = cudaMemset(d_entropy_candidates, 0, sizeof(unsigned long long));
    CUDA_CHECK_MALLOC(err, "cudaMemset failed for d_entropy_candidates");

    // Define optimal block and grid dimensions using occupancy calculator
    int min_grid_size = 0, block_size = 0;
    cudaOccupancyMaxPotentialBlockSize(&min_grid_size, &block_size, entropy_scan_kernel, 0, 0);

    // Ensure block size does not exceed device capability
    int max_threads_per_block;
    cudaDeviceGetAttribute(&max_threads_per_block, cudaDevAttrMaxThreadsPerBlock, 0);
    block_size = min(block_size, max_threads_per_block);

    // Define block and grid dimensions
    const int THREADS_PER_BLOCK = 1024;
    int total_threads = (haystack_length + BYTES_PER_THREAD - 1) / (BYTES_PER_THREAD * 100);
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