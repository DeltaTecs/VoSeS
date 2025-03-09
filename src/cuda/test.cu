#include "test.h"
#include <stdio.h>
#include <stdint.h>
#include <cuda_runtime.h>
#include "crypto/aes.h"
#include "crypto/sha256.h"

// CUDA kernel that encrypts one AES block using ECB mode
__global__ void aesEncryptKernel(uint8_t *d_data, const uint8_t *d_key) {
    // Create an AES context on the device
    AES_ctx ctx;
    // Initialize the context with the key
    for (int i = 0; i < 50000; i++) {
        cuda_AES_init_ctx(&ctx, d_key);
        // Encrypt the block (in-place encryption of a 16-byte buffer)
        cuda_AES_ECB_encrypt(&ctx, d_data);
    }
}

bool run_aes_test() {
    uint8_t h_key[AES_KEYLEN] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };
    uint8_t h_plaintext[AES_BLOCKLEN] = {
        '0','1','2','3','4','5','6','7',
        '8','9','A','B','C','D','E','F'
    };
    uint8_t h_expected_ciphertext[AES_BLOCKLEN] = {
        0x6f, 0x9c, 0x9e, 0x4a,
        0x27, 0xb3, 0xf9, 0x59,
        0xaf, 0x07, 0x51, 0xd8,
        0xfb, 0xfe, 0xc4, 0x93
    };

    uint8_t *d_key = NULL;
    uint8_t *d_data = NULL;
    cudaMalloc((void**)&d_key, AES_KEYLEN);
    cudaMalloc((void**)&d_data, AES_BLOCKLEN);
    cudaMemcpy(d_key, h_key, AES_KEYLEN, cudaMemcpyHostToDevice);
    cudaMemcpy(d_data, h_plaintext, AES_BLOCKLEN, cudaMemcpyHostToDevice);

    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start, 0);
    aesEncryptKernel<<<1, 1>>>(d_data, d_key);
    cudaEventRecord(stop, 0);
    cudaEventSynchronize(stop);

    float elapsedTime;
    cudaEventElapsedTime(&elapsedTime, start, stop);
    printf("AES ECB cuda runtime: %f ms\n", elapsedTime);

    uint8_t h_ciphertext[AES_BLOCKLEN];
    cudaMemcpy(h_ciphertext, d_data, AES_BLOCKLEN, cudaMemcpyDeviceToHost);

    bool success = true;

    for (int i = 0; i < AES_BLOCKLEN; i++) {
        if (h_ciphertext[i] != h_expected_ciphertext[i]) {
            success = false;
        }
    }

    if (success == false) {
        printf("AES encryption test FAIL! Mismatch with expected result. (50000 itr. ECB)\n");
    } else {
        printf("AES test pass\n");
    }

    cudaEventDestroy(start);
    cudaEventDestroy(stop);
    cudaFree(d_key);
    cudaFree(d_data);

    return success;
}


__global__ void sha256_test_kernel(const unsigned char *input, size_t input_len, unsigned char *digest) {
    // Each thread computes SHA-256 on its portion of the input
    cuda_sha256_2blocks(input, input_len, digest);
    for (int i = 0; i < 100000; i++) {
        cuda_sha256_2blocks(digest, input_len, digest);
    }
}

bool test_sha256() {
    unsigned char h_input[36] = { 
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c,
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c,
        0x3c, 0x3c, 0x3c, 0x3c };
    unsigned char h_expected_digest[32] = {0x64, 0x8b, 0x3f, 0x9e, 0xcc, 0xb7, 0xee, 0x40, 0xd5, 0xce, 0xc2, 0x62, 0xef, 0x52, 0x53, 0x97, 0xe4, 0xb1, 0xf2, 0xdf, 0x45, 0x65, 0xa7, 0x27, 0xe8, 0x09, 0x8a, 0x90, 0x66, 0xe9, 0x21, 0x89};
    unsigned char h_digest[32];

    unsigned char *d_input = NULL;
    unsigned char *d_digest = NULL;

    // Allocate device memory
    cudaMalloc((void**)&d_input, 36 * sizeof(unsigned char));
    cudaMalloc((void**)&d_digest, 36 * sizeof(unsigned char));

    // Copy input data from host to device
    cudaMemcpy(d_input, h_input, 36 * sizeof(unsigned char), cudaMemcpyHostToDevice);


    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start, 0);
    // Launch the SHA-256 kernel
    sha256_test_kernel<<<1, 1>>>(d_input, 36, d_digest);
    cudaEventRecord(stop, 0);
    cudaEventSynchronize(stop);
    float elapsedTime;
    cudaEventElapsedTime(&elapsedTime, start, stop);
    printf("SHA 256 cuda runtime: %f ms\n", elapsedTime);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);

    // Copy the digest from device to host
    cudaMemcpy(h_digest, d_digest, 32 * sizeof(unsigned char), cudaMemcpyDeviceToHost);

    bool success = true;
    for (int i = 0; i < 32; i++) {
        if (h_digest[i] != h_expected_digest[i]) {
            success = false;
        }
    }

    if (!success) {
        printf("SHA 256 encryption test FAIL! Mismatch with expected result. (100000 itr.)\n");
    } else {
        printf("SHA 256 test pass\n");
    }


    // Clean up
    cudaFree(d_input);
    cudaFree(d_digest);
    return true;
}


bool run_tests() {

    run_aes_test();
    test_sha256();
    return true;
}

int main() {
    run_tests();
}