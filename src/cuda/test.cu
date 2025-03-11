#include "test.h"
#include <stdio.h>
#include <stdint.h>
#include <cuda_runtime.h>
#include "crypto/aes.h"
#include "crypto/sha256.h"
#include "crypto/sha384.h"
#include "crypto/hmac-sha256.h"
#include "crypto/hmac-sha384.h"

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


__global__ void sha256_test_kernel(const unsigned char *input, short input_len, unsigned char *digest) {
    // Each thread computes SHA-256 on its portion of the input
    cuda_sha256(input, input_len, digest);
    for (int i = 0; i < 100000; i++) {
        cuda_sha256(digest, input_len, digest);
    }
}

__global__ void sha384_test_kernel(const unsigned char *input, short input_len, unsigned char *digest) {
    // Each thread computes SHA-256 on its portion of the input
    cuda_sha384(input, input_len, digest);
    for (int i = 0; i < 100000; i++) {
        cuda_sha384(digest, input_len, digest);
    }
}

__global__ void hmac_sha256_test_kernel(unsigned char *d_key, short key_len,
                                         const unsigned char *d_data, short data_len,
                                         unsigned char *d_hmac_result) {
    for (int i = 0; i < 50000; i++) {
        cuda_hmac_sha256_128data(d_key, key_len, d_data, data_len, d_hmac_result);
        d_key[0] ^= d_hmac_result[0];
        d_key[1] ^= d_hmac_result[2];
        d_key[5] ^= d_hmac_result[1];
    }
}

__global__ void hmac_sha384_test_kernel(unsigned char *d_key, short key_len,
                                         const unsigned char *d_data, short data_len,
                                         unsigned char *d_hmac_result) {
    for (int i = 0; i < 50000; i++) {
        cuda_hmac_sha384_128data(d_key, key_len, d_data, data_len, d_hmac_result);
        d_key[0] ^= d_hmac_result[0];
        d_key[1] ^= d_hmac_result[2];
        d_key[5] ^= d_hmac_result[1];
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
        printf("SHA 256 encryption test FAIL! Mismatch with expected result. (100001 itr.)\n");
    } else {
        printf("SHA 256 test pass\n");
    }


    // Clean up
    cudaFree(d_input);
    cudaFree(d_digest);
    return true;
}

bool test_sha384() {
    const int in_len = 144;
    unsigned char h_input[in_len] = { 0x40, 0x13, 0x9e, 0xd6, 0xbe, 0x12, 0x8f, 0x61, 0xc3, 0xd7, 0x68, 0xb9, 0x12, 0x31, 0x41, 0x7a, 0xbf, 0x4e, 0x5c, 0x81, 0x3b, 0xc3, 0xba, 0xfa, 0x81, 0x6c, 0xa9, 0x30, 0x02, 0xaa, 0x7b, 0xdf, 0x11, 0x49, 0x54, 0xe8, 0xe8, 0x1e, 0x95, 0x6d, 0x9f, 0x22, 0x8c, 0xb6, 0x5e, 0xa1, 0x56, 0x20, 0x40, 0x13, 0x9e, 0xd6, 0xbe, 0x12, 0x8f, 0x61, 0xc3, 0xd7, 0x68, 0xb9, 0x12, 0x31, 0x41, 0x7a, 0xbf, 0x4e, 0x5c, 0x81, 0x3b, 0xc3, 0xba, 0xfa, 0x81, 0x6c, 0xa9, 0x30, 0x02, 0xaa, 0x7b, 0xdf, 0x11, 0x49, 0x54, 0xe8, 0xe8, 0x1e, 0x95, 0x6d, 0x9f, 0x22, 0x8c, 0xb6, 0x5e, 0xa1, 0x56, 0x20, 0x40, 0x13, 0x9e, 0xd6, 0xbe, 0x12, 0x8f, 0x61, 0xc3, 0xd7, 0x68, 0xb9, 0x12, 0x31, 0x41, 0x7a, 0xbf, 0x4e, 0x5c, 0x81, 0x3b, 0xc3, 0xba, 0xfa, 0x81, 0x6c, 0xa9, 0x30, 0x02, 0xaa, 0x7b, 0xdf, 0x11, 0x49, 0x54, 0xe8, 0xe8, 0x1e, 0x95, 0x6d, 0x9f, 0x22, 0x8c, 0xb6, 0x5e, 0xa1, 0x56, 0x20};
    unsigned char h_expected_digest[48] = {0xe4, 0x98, 0x15, 0x3e, 0xb4, 0xda, 0x20, 0xfa, 0xb8, 0x34, 0x48, 0x69, 0x54, 0xc6, 0xdc, 0xa6, 0x53, 0xb5, 0xb4, 0x54, 0x4d, 0x8a, 0x38, 0x83, 0x17, 0x7f, 0x2c, 0xef, 0xf5, 0x75, 0x8e, 0xe2, 0xe8, 0x97, 0xd6, 0x8f, 0xdb, 0x3c, 0xe9, 0xa4, 0xff, 0x7d, 0xf1, 0x60, 0xb2, 0xc0, 0x1d, 0xd6};
    unsigned char h_digest[48];

    unsigned char *d_input = NULL;
    unsigned char *d_digest = NULL;

    // Allocate device memory
    cudaMalloc((void**)&d_input, in_len * sizeof(unsigned char));
    cudaMalloc((void**)&d_digest, 48 * sizeof(unsigned char));

    // Copy input data from host to device
    cudaMemcpy(d_input, h_input, in_len, cudaMemcpyHostToDevice);


    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start, 0);
    sha384_test_kernel<<<1, 1>>>(d_input, in_len, d_digest);
    cudaEventRecord(stop, 0);
    cudaEventSynchronize(stop);
    float elapsedTime;
    cudaEventElapsedTime(&elapsedTime, start, stop);
    printf("SHA 384 cuda runtime: %f ms\n", elapsedTime);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);

    // Copy the digest from device to host
    cudaMemcpy(h_digest, d_digest, 48 * sizeof(unsigned char), cudaMemcpyDeviceToHost);

    bool success = true;
    for (int i = 0; i < 48; i++) {
        if (h_digest[i] != h_expected_digest[i]) {
            success = false;
        }
    }
    
    if (!success) {
        printf("SHA 384 encryption test FAIL! Mismatch with expected result. (100001 itr.)\n");
    } else {
        printf("SHA 384 test pass\n");
    }


    // Clean up
    cudaFree(d_input);
    cudaFree(d_digest);
    return success;
}

bool test_hmac_sha256() {
    const int key_len = 48;
    const int data_len = 64;
    const int hmac_len = 32;
    
    unsigned char h_key[key_len] = { 
        0xaf, 0xab, 0xc9, 0x2e, 0x6a, 0xc6, 0xa0, 0xa7, 0x85, 0xb6, 0x51, 0x8c, 0x5b, 0xef, 0x8e, 0x10, 0x10, 0xd5, 0xec, 0x2c, 0x95, 0xe8, 0x82, 0x9c, 0xd7, 0x69, 0x38, 0x7e, 0x88, 0x40, 0xd7, 0x3d, 0xfb, 0xd0, 0xe1, 0x7f, 0x4c, 0x9b, 0xdd, 0xda, 0xcd, 0xc6, 0x1f, 0xef, 0x99, 0x2b, 0x3c, 0x06
    };
    unsigned char h_data[data_len] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c    };
    unsigned char h_hmac[hmac_len];
    unsigned char h_hmac_expected[hmac_len] = {
        0x12, 0xc5, 0x7f, 0xf6, 0xf1, 0x41, 0xbf, 0xa7, 0xa8, 0xe5, 0x49, 0x28, 0xb1, 0x45, 0x3c, 0xdf, 0xfe, 0xc1, 0x04, 0xb9, 0x46, 0x37, 0x18, 0x45, 0x8e, 0xc0, 0x96, 0x7a, 0x86, 0x10, 0xad, 0x41
    };


    // Allocate device memory.
    unsigned char *d_key, *d_data, *d_hmac;
    cudaMalloc((void**)&d_key, key_len * sizeof(unsigned char));
    cudaMalloc((void**)&d_data, data_len * sizeof(unsigned char));
    cudaMalloc((void**)&d_hmac, hmac_len * sizeof(unsigned char));

    // Copy host memory to device.
    cudaMemcpy(d_key, h_key, key_len * sizeof(unsigned char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_data, h_data, data_len * sizeof(unsigned char), cudaMemcpyHostToDevice);

    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start, 0);
    hmac_sha256_test_kernel<<<1, 1>>>(d_key, key_len, d_data, data_len, d_hmac);
    cudaDeviceSynchronize();
    cudaEventRecord(stop, 0);
    cudaEventSynchronize(stop);
    float elapsedTime;
    cudaEventElapsedTime(&elapsedTime, start, stop);
    printf("HMAC SHA 256 cuda runtime: %f ms\n", elapsedTime);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);

    // Copy the HMAC result back to host.
    cudaMemcpy(h_hmac, d_hmac, hmac_len * sizeof(unsigned char), cudaMemcpyDeviceToHost);

    bool success = true;
    for (int i = 0; i < 48; i++) {
        if (h_hmac[i] != h_hmac_expected[i]) {
            success = false;
        }
    }
    
    if (!success) {
        printf("HMAC SHA 256 encryption test FAIL! Mismatch with expected result. (50000 itr.)\n");
    } else {
        printf("HMAC SHA 256 test pass\n");
    }

    // Free device memory.
    cudaFree(d_key);
    cudaFree(d_data);
    cudaFree(d_hmac);
    return success;
}

bool test_hmac_sha384() {
    const int key_len  = 48;
    const int data_len = 64;
    const int hmac_len = 48;   // SHA-384 produces 384 bits (48 bytes)

    unsigned char h_key[key_len] = { 
        0xaf, 0xab, 0xc9, 0x2e, 0x6a, 0xc6, 0xa0, 0xa7, 0x85, 0xb6, 0x51, 0x8c, 0x5b, 0xef, 0x8e, 0x10, 0x10, 0xd5, 0xec, 0x2c, 0x95, 0xe8, 0x82, 0x9c, 0xd7, 0x69, 0x38, 0x7e, 0x88, 0x40, 0xd7, 0x3d, 0xfb, 0xd0, 0xe1, 0x7f, 0x4c, 0x9b, 0xdd, 0xda, 0xcd, 0xc6, 0x1f, 0xef, 0x99, 0x2b, 0x3c, 0x06
    };

    unsigned char h_data[data_len] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    unsigned char h_hmac[hmac_len];
    // Expected HMAC-SHA384 result computed by a reference implementation.
    unsigned char h_hmac_expected[hmac_len] = {
        0xf4, 0xc5, 0x4b, 0xea, 0x00, 0x79, 0x59, 0x8b, 0x7d, 0xf2, 0x1c, 0xc6, 0x2f, 0x39, 0xe2, 0xf1, 0x1f, 0xb6, 0x8b, 0xcc, 0x78, 0x30, 0x2a, 0xbf, 0x47, 0x9c, 0xcc, 0xd1, 0x22, 0x88, 0x9a, 0xa8, 0xa4, 0x34, 0xa3, 0x2e, 0xa1, 0xb4, 0xb8, 0x5f, 0x59, 0x9d, 0x5f, 0xe9, 0xed, 0xc7, 0xe2, 0xab
    };

    // Allocate device memory.
    unsigned char *d_key, *d_data, *d_hmac;
    cudaMalloc((void**)&d_key, key_len * sizeof(unsigned char));
    cudaMalloc((void**)&d_data, data_len * sizeof(unsigned char));
    cudaMalloc((void**)&d_hmac, hmac_len * sizeof(unsigned char));

    // Copy host memory to device.
    cudaMemcpy(d_key, h_key, key_len * sizeof(unsigned char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_data, h_data, data_len * sizeof(unsigned char), cudaMemcpyHostToDevice);

    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start, 0);
    // Launch the HMAC-SHA384 test kernel.
    hmac_sha384_test_kernel<<<1, 1>>>(d_key, key_len, d_data, data_len, d_hmac);
    cudaDeviceSynchronize();
    cudaEventRecord(stop, 0);
    cudaEventSynchronize(stop);
    float elapsedTime;
    cudaEventElapsedTime(&elapsedTime, start, stop);
    printf("HMAC SHA 384 cuda runtime: %f ms\n", elapsedTime);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);

    // Copy the HMAC result back to host.
    cudaMemcpy(h_hmac, d_hmac, hmac_len * sizeof(unsigned char), cudaMemcpyDeviceToHost);

    bool success = true;
    for (int i = 0; i < hmac_len; i++) {
        if (h_hmac[i] != h_hmac_expected[i]) {
            success = false;
            break;
        }
    }
    
    if (!success) {
        printf("HMAC SHA 384 test FAIL! Mismatch with expected result.\n");
    } else {
        printf("HMAC SHA 384 test pass\n");
    }

    // Free device memory.
    cudaFree(d_key);
    cudaFree(d_data);
    cudaFree(d_hmac);
    return success;
}



bool run_tests() {

    run_aes_test();
    test_sha256();
    test_sha384();
    test_hmac_sha256();
    test_hmac_sha384();
    return true;
}

int main() {
    run_tests();
}