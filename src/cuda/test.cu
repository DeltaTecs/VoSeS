#include "test.h"
#include <stdio.h>
#include <stdint.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cuda_runtime.h>
#include <limits>
#include "crypto/aes128.h"
#include "crypto/aes256.h"
#include "crypto/sha256.h"
#include "crypto/sha384.h"
#include "crypto/hmac-sha256.h"
#include "crypto/hmac-sha384.h"
#include "crypto/kdf.h"
#include "crypto/gcm128.h"
#include "extract/tls12/tls12-gcm-extract.h"
#include "extract/tls13/tls13-gcm-extract.h"
#include "extract/quic/quic-gcm-extract.h"
#include "extract/extractor.h"
#include "../host_util.h"

__global__ void full_verify_gcm128(unsigned char* d_result, const unsigned char* d_master_secret, short master_secret_len,
                                   unsigned char d_client_random[32], unsigned char d_server_random[32], uint64_t seq_num,
                                   unsigned char* d_aad, short aad_length, unsigned char* d_chiphertext, short ciphertext_length) {
    // Assumes we are given the client finished message as cipher text and hence uses client write keys / iv
    *d_result = 1;

    for (int i = 0; i < 10000; i++) {
        bool valid = cuda_match_master_secret_gcm128_sha256(d_master_secret, master_secret_len, d_client_random, d_server_random, seq_num, d_aad, aad_length, d_chiphertext, ciphertext_length);
        *d_result = d_result && valid;
    }
}

__global__ void tls13_verify_gcm128(unsigned char* d_result, const unsigned char* d_app_traffic_secret_0, short app_traffic_secret_len,
                                    uint64_t seq_num, unsigned char* d_aad, short aad_length,
                                    unsigned char* d_chiphertext, short ciphertext_length) {
    *d_result = cuda_match_app_traffic_secret_0_gcm128_sha256(d_app_traffic_secret_0, app_traffic_secret_len,
                                                              seq_num, d_aad, aad_length,
                                                              d_chiphertext, ciphertext_length);
}

__global__ void tls13_verify_gcm256(unsigned char* d_result, const unsigned char* d_app_traffic_secret_0, short app_traffic_secret_len,
                                    uint64_t seq_num, unsigned char* d_aad, short aad_length,
                                    unsigned char* d_chiphertext, short ciphertext_length) {
    *d_result = cuda_match_app_traffic_secret_0_gcm256_sha384(d_app_traffic_secret_0, app_traffic_secret_len,
                                                              seq_num, d_aad, aad_length,
                                                              d_chiphertext, ciphertext_length);
}

__global__ void quic_verify_gcm128(unsigned char* d_result, const unsigned char* d_app_traffic_secret_0, short app_traffic_secret_len,
                                   const unsigned char* d_packet, short packet_length, short pn_offset) {
    *d_result = cuda_match_quic_app_traffic_secret_0_gcm128_sha256(d_app_traffic_secret_0, app_traffic_secret_len,
                                                                   d_packet, packet_length, pn_offset);
}

// CUDA kernel that encrypts one AES block using ECB mode
__global__ void aes128EncryptKernel(uint8_t *d_data, const uint8_t *d_key) {
    // Create an AES context on the device
    AES128_ctx ctx;
    // Initialize the context with the key
    for (int i = 0; i < 50000; i++) {
        cuda_AES128_init_ctx(&ctx, d_key);
        // Encrypt the block (in-place encryption of a 16-byte buffer)
        cuda_AES128_ECB_encrypt(&ctx, d_data);
    }
}

// CUDA kernel that encrypts one AES block using ECB mode
__global__ void aes256EncryptKernel(uint8_t *d_data, const uint8_t *d_key) {
    // Create an AES context on the device
    AES256_ctx ctx;
    // Initialize the context with the key
    for (int i = 0; i < 50000; i++) {
        cuda_AES256_init_ctx(&ctx, d_key);
        // Encrypt the block (in-place encryption of a 16-byte buffer)
        cuda_AES256_ECB_encrypt(&ctx, d_data);
    }
}

__global__ void device_check_kernel(int *d_res) {
    *d_res = 1337;
}

bool test_device_availability() {
    // 1) Explicitly check if the system has at least one CUDA-capable device.
    int deviceCount = 0;
    cudaError_t err = cudaGetDeviceCount(&deviceCount);
    if (err != cudaSuccess) {
        printf("cudaGetDeviceCount failed: %s\n", cudaGetErrorString(err));
        return false;
    }
    if (deviceCount <= 0) {
        printf("No CUDA-capable devices detected.\n");
        return false;
    }

    // Pick the first device with a non-zero compute capability.
    int selectedDevice = -1;
    for (int dev = 0; dev < deviceCount; dev++) {
        cudaDeviceProp prop;
        cudaError_t propErr = cudaGetDeviceProperties(&prop, dev);
        if (propErr != cudaSuccess) {
            printf("cudaGetDeviceProperties(%d) failed: %s\n", dev, cudaGetErrorString(propErr));
            continue;
        }

        printf("CUDA device %d: %s (cc %d.%d, globalMem %zu bytes)\n",
               dev, prop.name, prop.major, prop.minor, (size_t)prop.totalGlobalMem);

        if (prop.major > 0) {
            selectedDevice = dev;
            break;
        }
    }

    if (selectedDevice < 0) {
        printf("CUDA runtime reports devices, but none appear CUDA-capable (compute capability 0.x).\n");
        return false;
    }

    err = cudaSetDevice(selectedDevice);
    if (err != cudaSuccess) {
        printf("cudaSetDevice(%d) failed: %s\n", selectedDevice, cudaGetErrorString(err));
        return false;
    }

    // 2) Functional smoke test: allocate, launch a trivial kernel, sync, memcpy.
    int *d_res = NULL;
    int h_res = 0;

    err = cudaMalloc((void**)&d_res, sizeof(int));
    if (err != cudaSuccess) {
        printf("CUDA malloc failed: %s\n", cudaGetErrorString(err));
        return false;
    }

    device_check_kernel<<<1, 1>>>(d_res);
    
    err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Kernel launch failed: %s\n", cudaGetErrorString(err));
        cudaFree(d_res);
        return false;
    }

    err = cudaDeviceSynchronize();
    if (err != cudaSuccess) {
        printf("CUDA synchronize failed: %s\n", cudaGetErrorString(err));
        cudaFree(d_res);
        return false;
    }

    err = cudaMemcpy(&h_res, d_res, sizeof(int), cudaMemcpyDeviceToHost);
    if (err != cudaSuccess) {
        printf("CUDA memcpy failed: %s\n", cudaGetErrorString(err));
        cudaFree(d_res);
        return false;
    }

    cudaFree(d_res);

    if (h_res == 1337) {
        printf("Device availability test pass\n");
        return true;
    } else {
        printf("Device availability test FAIL! Expected 1337, got %d\n", h_res);
        return false;
    }
}

bool run_aes128_test() {
    const int keylen = 16;
    uint8_t h_key[keylen] = {
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
    cudaMalloc((void**)&d_key, keylen);
    cudaMalloc((void**)&d_data, AES_BLOCKLEN);
    cudaMemcpy(d_key, h_key, keylen, cudaMemcpyHostToDevice);
    cudaMemcpy(d_data, h_plaintext, AES_BLOCKLEN, cudaMemcpyHostToDevice);

    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start, 0);
    aes128EncryptKernel<<<1, 1>>>(d_data, d_key);
    cudaEventRecord(stop, 0);
    cudaEventSynchronize(stop);

    float elapsedTime;
    cudaEventElapsedTime(&elapsedTime, start, stop);
    printf("AES 128 ECB cuda runtime: %f ms\n", elapsedTime);

    uint8_t h_ciphertext[AES_BLOCKLEN];
    cudaMemcpy(h_ciphertext, d_data, AES_BLOCKLEN, cudaMemcpyDeviceToHost);

    bool success = true;

    for (int i = 0; i < AES_BLOCKLEN; i++) {
        if (h_ciphertext[i] != h_expected_ciphertext[i]) {
            success = false;
        }
    }

    if (success == false) {
        printf("AES 128 encryption test FAIL! Mismatch with expected result. (50000 itr. ECB)\n");
    } else {
        printf("AES 128 test pass\n");
    }

    cudaEventDestroy(start);
    cudaEventDestroy(stop);
    cudaFree(d_key);
    cudaFree(d_data);

    return success;
}

bool run_aes256_test() {
    const int keylen = 32;
    uint8_t h_key[keylen] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c,
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };
    uint8_t h_plaintext[AES_BLOCKLEN] = {
        '0','1','2','3','4','5','6','7',
        '8','9','A','B','C','D','E','F',
    };
    uint8_t h_expected_ciphertext[AES_BLOCKLEN] = {
        0xCF, 0xDC, 0xAC, 0x80, 0xDE, 0x83, 0x1C, 0x8B, 0x51, 0xA4, 0x24, 0x99, 0x3E, 0x4C, 0x63, 0xDF
    };

    uint8_t *d_key = NULL;
    uint8_t *d_data = NULL;
    cudaMalloc((void**)&d_key, keylen);
    cudaMalloc((void**)&d_data, AES_BLOCKLEN);
    cudaMemcpy(d_key, h_key, keylen, cudaMemcpyHostToDevice);
    cudaMemcpy(d_data, h_plaintext, AES_BLOCKLEN, cudaMemcpyHostToDevice);

    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start, 0);
    aes256EncryptKernel<<<1, 1>>>(d_data, d_key);
    cudaEventRecord(stop, 0);
    cudaEventSynchronize(stop);

    float elapsedTime;
    cudaEventElapsedTime(&elapsedTime, start, stop);
    printf("AES 256 ECB cuda runtime: %f ms\n", elapsedTime);

    uint8_t h_ciphertext[AES_BLOCKLEN];
    cudaMemcpy(h_ciphertext, d_data, AES_BLOCKLEN, cudaMemcpyDeviceToHost);

    bool success = true;

    for (int i = 0; i < AES_BLOCKLEN; i++) {
        if (h_ciphertext[i] != h_expected_ciphertext[i]) {
            success = false;
        }
    }

    if (success == false) {
        printf("AES 256 encryption test FAIL! Mismatch with expected result. (50000 itr. ECB)\n");
    } else {
        printf("AES 256 test pass\n");
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

__global__ void tls13_key_derivation_kernel(unsigned char *d_secret, short secret_len,
                                            unsigned char *d_key, unsigned char *d_iv) {
    const short key_len = 16;
    short iter_secret_len = secret_len;
    for (int i = 0; i < 5000; i++) {
        cuda_derive_tls13_key_128(d_secret, iter_secret_len, d_key, d_iv);
        for (int i = 0; i < key_len && i < secret_len; i++) {
            d_secret[i] ^= d_key[i];
        }
        iter_secret_len = key_len;
    }
}

__global__ void tls13_key_derivation_256_kernel(unsigned char *d_secret, short secret_len,
                                                unsigned char *d_key, unsigned char *d_iv) {
    const short key_len = 32;
    short iter_secret_len = secret_len;
    for (int i = 0; i < 5000; i++) {
        cuda_derive_tls13_key_256(d_secret, iter_secret_len, d_key, d_iv);
        for (int i = 0; i < key_len && i < secret_len; i++) {
            d_secret[i] ^= d_key[i];
        }
        iter_secret_len = key_len;
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
    for (int i = 0; i < hmac_len; i++) {
        if (h_hmac[i] != h_hmac_expected[i]) {
            success = false;
            break;
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

bool test_tls13_key_derivation() {
    const int secret_len = 32;
    const int key_len = 16;
    const int iv_len = 12;

    unsigned char h_secret[secret_len] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    // Generated via Python HKDF-Expand-Label (SHA-256) for secret 0x00..0x1f
    // with 5000 iterations updating secret ^= key each round (first 16 bytes).
    unsigned char h_expected_key[key_len] = {
        0x5e, 0x14, 0xac, 0x0d, 0xf2, 0x21, 0x62, 0x6e,
        0x37, 0x96, 0x2b, 0xd4, 0x56, 0x85, 0x74, 0xf4
    };
    unsigned char h_expected_iv[iv_len] = {
        0xce, 0xee, 0xde, 0x3f, 0x64, 0x2f, 0x84, 0x22,
        0x5d, 0x4f, 0xba, 0x15
    };
    unsigned char h_key[key_len];
    unsigned char h_iv[iv_len];

    unsigned char *d_secret = NULL;
    unsigned char *d_key = NULL;
    unsigned char *d_iv = NULL;

    cudaMalloc((void**)&d_secret, secret_len * sizeof(unsigned char));
    cudaMalloc((void**)&d_key, key_len * sizeof(unsigned char));
    cudaMalloc((void**)&d_iv, iv_len * sizeof(unsigned char));
    cudaMemcpy(d_secret, h_secret, secret_len * sizeof(unsigned char), cudaMemcpyHostToDevice);

    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start, 0);
    tls13_key_derivation_kernel<<<1, 1>>>(d_secret, secret_len, d_key, d_iv);
    cudaEventRecord(stop, 0);
    cudaEventSynchronize(stop);
    float elapsedTime;
    cudaEventElapsedTime(&elapsedTime, start, stop);
    printf("TLS 1.3 key derivation cuda runtime: %f ms\n", elapsedTime);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);

    cudaMemcpy(h_key, d_key, key_len * sizeof(unsigned char), cudaMemcpyDeviceToHost);
    cudaMemcpy(h_iv, d_iv, iv_len * sizeof(unsigned char), cudaMemcpyDeviceToHost);

    bool success = true;
    for (int i = 0; i < key_len; i++) {
        if (h_key[i] != h_expected_key[i]) {
            success = false;
            break;
        }
    }
    if (success) {
        for (int i = 0; i < iv_len; i++) {
            if (h_iv[i] != h_expected_iv[i]) {
                success = false;
                break;
            }
        }
    }

    if (!success) {
        printf("TLS 1.3 key derivation test FAIL! Mismatch with expected result.\n");
    } else {
        printf("TLS 1.3 key derivation test pass\n");
    }

    cudaFree(d_secret);
    cudaFree(d_key);
    cudaFree(d_iv);
    return success;
}

bool test_tls13_key_derivation_256() {
    const int secret_len = 48;
    const int key_len = 32;
    const int iv_len = 12;

    unsigned char h_secret[secret_len] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    };
    // Generated via Python HKDF-Expand-Label (SHA-384) for secret 0x00..0x2f
    // with 5000 iterations updating secret ^= key each round (first 32 bytes).
    unsigned char h_expected_key[key_len] = {
        0x44, 0xcc, 0x1e, 0x83, 0x31, 0x0d, 0x40, 0xc1,
        0x44, 0xb6, 0x48, 0xb2, 0xa6, 0xb6, 0x9e, 0x08,
        0x71, 0xe8, 0x4c, 0x43, 0x9f, 0xbf, 0x46, 0x89,
        0x2c, 0x45, 0xc2, 0x1f, 0x61, 0x58, 0x15, 0x8e
    };
    unsigned char h_expected_iv[iv_len] = {
        0xb0, 0x81, 0xb6, 0x7f, 0x8e, 0xe0, 0x2c, 0x63,
        0xb0, 0xe9, 0x97, 0x06
    };
    unsigned char h_key[key_len];
    unsigned char h_iv[iv_len];

    unsigned char *d_secret = NULL;
    unsigned char *d_key = NULL;
    unsigned char *d_iv = NULL;

    cudaMalloc((void**)&d_secret, secret_len * sizeof(unsigned char));
    cudaMalloc((void**)&d_key, key_len * sizeof(unsigned char));
    cudaMalloc((void**)&d_iv, iv_len * sizeof(unsigned char));
    cudaMemcpy(d_secret, h_secret, secret_len * sizeof(unsigned char), cudaMemcpyHostToDevice);

    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start, 0);
    tls13_key_derivation_256_kernel<<<1, 1>>>(d_secret, secret_len, d_key, d_iv);
    cudaEventRecord(stop, 0);
    cudaEventSynchronize(stop);
    float elapsedTime;
    cudaEventElapsedTime(&elapsedTime, start, stop);
    printf("TLS 1.3 key derivation (AES-256) cuda runtime: %f ms\n", elapsedTime);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);

    cudaMemcpy(h_key, d_key, key_len * sizeof(unsigned char), cudaMemcpyDeviceToHost);
    cudaMemcpy(h_iv, d_iv, iv_len * sizeof(unsigned char), cudaMemcpyDeviceToHost);

    bool success = true;
    for (int i = 0; i < key_len; i++) {
        if (h_key[i] != h_expected_key[i]) {
            success = false;
            break;
        }
    }
    if (success) {
        for (int i = 0; i < iv_len; i++) {
            if (h_iv[i] != h_expected_iv[i]) {
                success = false;
                break;
            }
        }
    }

    if (!success) {
        printf("TLS 1.3 key derivation (AES-256) test FAIL! Mismatch with expected result.\n");
    } else {
        printf("TLS 1.3 key derivation (AES-256) test pass\n");
    }

    cudaFree(d_secret);
    cudaFree(d_key);
    cudaFree(d_iv);
    return success;
}

bool test_tls13_app_traffic_secret_gcm128_sha256() {
    // Generated via Python HKDF-Expand-Label (SHA-256) + AES-GCM with seq_num=5.
    std::string app_traffic_secret = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    std::string aad_hex = "1703030020";
    std::string ciphertext_hex = "09f7c03470ed108b2ed8bfbe5e2c4da925734825e6b5ad53a4493f65514ea966";
    uint64_t seq_num = 5;

    std::vector<unsigned char> secret_bytes = hexStringToByteArray(app_traffic_secret);
    std::vector<unsigned char> aad_bytes = hexStringToByteArray(aad_hex);
    std::vector<unsigned char> ciphertext_bytes = hexStringToByteArray(ciphertext_hex);

    unsigned char* d_result = nullptr;
    unsigned char* d_secret = nullptr;
    unsigned char* d_aad = nullptr;
    unsigned char* d_chiphertext = nullptr;

    cudaMalloc((void**)&d_result, sizeof(unsigned char));
    cudaMalloc((void**)&d_secret, secret_bytes.size() * sizeof(unsigned char));
    cudaMalloc((void**)&d_aad, aad_bytes.size() * sizeof(unsigned char));
    cudaMalloc((void**)&d_chiphertext, ciphertext_bytes.size() * sizeof(unsigned char));

    cudaMemcpy(d_secret, secret_bytes.data(), secret_bytes.size() * sizeof(unsigned char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_aad, aad_bytes.data(), aad_bytes.size() * sizeof(unsigned char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_chiphertext, ciphertext_bytes.data(), ciphertext_bytes.size() * sizeof(unsigned char), cudaMemcpyHostToDevice);

    short secret_len = static_cast<short>(secret_bytes.size());
    short aad_length = static_cast<short>(aad_bytes.size());
    short ciphertext_length = static_cast<short>(ciphertext_bytes.size());

    tls13_verify_gcm128<<<1, 1>>>(d_result, d_secret, secret_len,
                                  seq_num, d_aad, aad_length,
                                  d_chiphertext, ciphertext_length);
    cudaDeviceSynchronize();

    unsigned char h_result = 0;
    cudaMemcpy(&h_result, d_result, sizeof(unsigned char), cudaMemcpyDeviceToHost);
    bool success = (h_result != 0);

    if (!success) {
        printf("TLS 1.3 app traffic secret GCM128 test FAIL!\n");
    } else {
        printf("TLS 1.3 app traffic secret GCM128 test pass\n");
    }

    cudaFree(d_result);
    cudaFree(d_secret);
    cudaFree(d_aad);
    cudaFree(d_chiphertext);

    return success;
}

bool test_tls13_app_traffic_secret_gcm256_sha384() {
    // Generated via Python HKDF-Expand-Label (SHA-384) + AES-GCM with seq_num=7.
    std::string app_traffic_secret = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
    std::string aad_hex = "1703030024";
    std::string ciphertext_hex = "a6025e5797aab62289d20d7a7b3d404323aa0ebce015abb1fb6410886f4c7f70b8100555";
    uint64_t seq_num = 7;

    std::vector<unsigned char> secret_bytes = hexStringToByteArray(app_traffic_secret);
    std::vector<unsigned char> aad_bytes = hexStringToByteArray(aad_hex);
    std::vector<unsigned char> ciphertext_bytes = hexStringToByteArray(ciphertext_hex);

    unsigned char* d_result = nullptr;
    unsigned char* d_secret = nullptr;
    unsigned char* d_aad = nullptr;
    unsigned char* d_chiphertext = nullptr;

    cudaMalloc((void**)&d_result, sizeof(unsigned char));
    cudaMalloc((void**)&d_secret, secret_bytes.size() * sizeof(unsigned char));
    cudaMalloc((void**)&d_aad, aad_bytes.size() * sizeof(unsigned char));
    cudaMalloc((void**)&d_chiphertext, ciphertext_bytes.size() * sizeof(unsigned char));

    cudaMemcpy(d_secret, secret_bytes.data(), secret_bytes.size() * sizeof(unsigned char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_aad, aad_bytes.data(), aad_bytes.size() * sizeof(unsigned char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_chiphertext, ciphertext_bytes.data(), ciphertext_bytes.size() * sizeof(unsigned char), cudaMemcpyHostToDevice);

    short secret_len = static_cast<short>(secret_bytes.size());
    short aad_length = static_cast<short>(aad_bytes.size());
    short ciphertext_length = static_cast<short>(ciphertext_bytes.size());

    tls13_verify_gcm256<<<1, 1>>>(d_result, d_secret, secret_len,
                                  seq_num, d_aad, aad_length,
                                  d_chiphertext, ciphertext_length);
    cudaDeviceSynchronize();

    unsigned char h_result = 0;
    cudaMemcpy(&h_result, d_result, sizeof(unsigned char), cudaMemcpyDeviceToHost);
    bool success = (h_result != 0);

    if (!success) {
        printf("TLS 1.3 app traffic secret GCM256 test FAIL!\n");
    } else {
        printf("TLS 1.3 app traffic secret GCM256 test pass\n");
    }

    cudaFree(d_result);
    cudaFree(d_secret);
    cudaFree(d_aad);
    cudaFree(d_chiphertext);

    return success;
}

bool test_quic_app_traffic_secret_gcm128_sha256() {
    std::string app_traffic_secret = "94048e2729a46528da18059848c02ae2ac434643644018b7f10ec70a8110109a";
    std::string packet_hex = "5101d3f04c63fca7a6b3d18d4c83fcbf5a113eb363e4f385b9288f358171324e6e38b9b189700091961797cebe5dba22cbd3a0be5f999e4fc2c7cab8c7e78d76169ec5bfa9013eb487161635948d4ca8f9950c40dda9";

    std::vector<unsigned char> secret_bytes = hexStringToByteArray(app_traffic_secret);
    std::vector<unsigned char> packet_bytes = hexStringToByteArray(packet_hex);

    if (secret_bytes.size() != 32 || packet_bytes.empty()) {
        printf("QUIC test FAIL! Invalid input sizes.\n");
        return false;
    }
    if (packet_bytes.size() > static_cast<size_t>(std::numeric_limits<short>::max())) {
        printf("QUIC test FAIL! Packet too large for CUDA parameters.\n");
        return false;
    }

    unsigned char* d_result = nullptr;
    unsigned char* d_secret = nullptr;
    unsigned char* d_packet = nullptr;

    cudaMalloc((void**)&d_result, sizeof(unsigned char));
    cudaMalloc((void**)&d_secret, secret_bytes.size() * sizeof(unsigned char));
    cudaMalloc((void**)&d_packet, packet_bytes.size() * sizeof(unsigned char));

    cudaMemcpy(d_secret, secret_bytes.data(), secret_bytes.size() * sizeof(unsigned char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_packet, packet_bytes.data(), packet_bytes.size() * sizeof(unsigned char), cudaMemcpyHostToDevice);

    bool success = false;
    int matched_dcid_len = -1;
    unsigned char h_result = 0;
    short packet_length = static_cast<short>(packet_bytes.size());
    short secret_length = static_cast<short>(secret_bytes.size());

    // Short headers require a known DCID length; brute-force 0..20 to recover pn_offset.
    for (int dcid_len = 0; dcid_len <= 20; dcid_len++) {
        short pn_offset = static_cast<short>(1 + dcid_len);
        if (pn_offset >= packet_length) {
            continue;
        }
        quic_verify_gcm128<<<1, 1>>>(d_result, d_secret, secret_length, d_packet, packet_length, pn_offset);
        cudaDeviceSynchronize();
        cudaMemcpy(&h_result, d_result, sizeof(unsigned char), cudaMemcpyDeviceToHost);
        if (h_result != 0) {
            success = true;
            matched_dcid_len = dcid_len;
            break;
        }
    }

    if (!success) {
        printf("QUIC app traffic secret test FAIL! No matching dcid_len found.\n");
    } else {
        printf("QUIC app traffic secret test pass (dcid_len=%d)\n", matched_dcid_len);
    }

    cudaFree(d_result);
    cudaFree(d_secret);
    cudaFree(d_packet);

    return success;
}

bool test_full_gcm128() {

    std::string master_secret = "afabc92e6ac6a0a785b6518c5bef8e1010d5ec2c95e8829cd769387e8840d73dfbd0e17f4c9bdddacdc61fef992b3c06";
    std::string client_random = "0ba3746e1d0972175c645e563cef8341a9b3b2e8cbec214e11844ac0a69a6966";
    std::string server_random = "c98c71e2fa221d00a47237c00c8218ecc45c5e39dc38de02067b1ebb1b82363b";
    std::string client_finished = "16030300280000000000000000ff70e3ef3816eb9b7f32a1223938ede383600b1f188be8920a63c27045fbfc75";
    std::vector<unsigned char> master_secret_bytes = hexStringToByteArray(master_secret);
    std::vector<unsigned char> client_random_bytes = hexStringToByteArray(client_random);
    std::vector<unsigned char> server_random_bytes = hexStringToByteArray(server_random);
    std::vector<unsigned char> client_finished_bytes = hexStringToByteArray(client_finished);

    const int AAD_LENGTH = 13;

    // extract cipher text
    const int ciphertext_len = client_finished_bytes.size() - AAD_LENGTH;
    unsigned char* ciphertext_bytes = (unsigned char*) malloc(ciphertext_len);
    memcpy(ciphertext_bytes, client_finished_bytes.data() + AAD_LENGTH, ciphertext_len);

    uint64_t target_seq_num = 0;
    memcpy(&target_seq_num, client_finished_bytes.data() + 5, 8);

    // setup associated data
    unsigned char* aad_bytes = (unsigned char*) malloc(AAD_LENGTH);
    memcpy(aad_bytes, &target_seq_num, 8);
    aad_bytes[ 8] = 0x16; // type handshake
    aad_bytes[ 9] = 0x03; // version tls 1.2
    aad_bytes[10] = 0x03; // version tls 1.2
    aad_bytes[11] = 0x00; // encode length of encrypted finished message (always 12 bytes -> 16 bytes when padded)
    aad_bytes[12] = 0x10; // encode length of encrypted finished message (always 12 bytes -> 16 bytes when padded)

    unsigned char* d_result = nullptr;
    unsigned char* d_master_secret = nullptr;
    unsigned char* d_client_random = nullptr;
    unsigned char* d_server_random = nullptr;
    unsigned char* d_aad = nullptr;
    unsigned char* d_chiphertext = nullptr;

    cudaMalloc((void**)&d_result, sizeof(unsigned char));
    cudaMalloc((void**)&d_master_secret, master_secret_bytes.size() * sizeof(unsigned char));
    cudaMalloc((void**)&d_client_random, 32 * sizeof(unsigned char));
    cudaMalloc((void**)&d_server_random, 32 * sizeof(unsigned char));
    cudaMalloc((void**)&d_aad, AAD_LENGTH * sizeof(unsigned char));
    cudaMalloc((void**)&d_chiphertext, ciphertext_len * sizeof(unsigned char));

    cudaMemcpy(d_master_secret, master_secret_bytes.data(), master_secret_bytes.size(), cudaMemcpyHostToDevice);
    cudaMemcpy(d_client_random, client_random_bytes.data(), 32 * sizeof(unsigned char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_server_random, server_random_bytes.data(), 32 * sizeof(unsigned char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_aad, aad_bytes, AAD_LENGTH * sizeof(unsigned char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_chiphertext, ciphertext_bytes, ciphertext_len * sizeof(unsigned char), cudaMemcpyHostToDevice);

    short master_secret_len = master_secret_bytes.size();
    short aad_length = AAD_LENGTH;
    short ciphertext_length = ciphertext_len;

    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start, 0);
    // Launch the HMAC-SHA384 test kernel.
    full_verify_gcm128<<<1, 1>>>(d_result, d_master_secret, master_secret_len,
                                                      d_client_random, d_server_random, target_seq_num,
                                                      d_aad, aad_length, d_chiphertext, ciphertext_length);
    cudaDeviceSynchronize();
    cudaEventRecord(stop, 0);
    cudaEventSynchronize(stop);
    float elapsedTime;
    cudaEventElapsedTime(&elapsedTime, start, stop);
    printf("full verification runtime: %f ms\n", elapsedTime);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);

    unsigned char h_result = 0;
    cudaMemcpy(&h_result, d_result, sizeof(unsigned char), cudaMemcpyDeviceToHost);
    bool success = (h_result != 0);

    if (!success) {
        printf("full gcm check test FAIL!\n");
    } else {
        printf("full gcm check success\n");
    }

    // Free device memory.
    cudaFree(d_result);
    cudaFree(d_master_secret);
    cudaFree(d_client_random);
    cudaFree(d_server_random);
    cudaFree(d_aad);
    cudaFree(d_chiphertext);

    // Free host allocated memory.
    free(ciphertext_bytes);
    free(aad_bytes);
    return success;
}

bool test_tls13_app_traffic_secret_gcm128_sha256_match() {
    // User provided case
    std::string app_traffic_secret = "2f04cf52fa8ce49d2a95869b55057be3541bb2a82768630a01d9558609dcd0d0";
    std::string aad_hex = "1703030057";
    std::string ciphertext_hex = "3b4aab0d4d225d605a4252ca602a8dab3572f7682afed4cbded2eebdc20abfc77951401dcb2a9f526caea93daa6ff52863363f2fcd2fa4b5235abc4b82e35b147c33fae786c9dabf6453bb4a11dcdb4fde19df89c98f16";
    uint64_t seq_num = 0;

    std::vector<unsigned char> secret_bytes = hexStringToByteArray(app_traffic_secret);
    std::vector<unsigned char> aad_bytes = hexStringToByteArray(aad_hex);
    std::vector<unsigned char> ciphertext_bytes = hexStringToByteArray(ciphertext_hex);

    unsigned char* d_result = nullptr;
    unsigned char* d_secret = nullptr;
    unsigned char* d_aad = nullptr;
    unsigned char* d_chiphertext = nullptr;

    cudaMalloc((void**)&d_result, sizeof(unsigned char));
    cudaMalloc((void**)&d_secret, secret_bytes.size() * sizeof(unsigned char));
    cudaMalloc((void**)&d_aad, aad_bytes.size() * sizeof(unsigned char));
    cudaMalloc((void**)&d_chiphertext, ciphertext_bytes.size() * sizeof(unsigned char));

    cudaMemcpy(d_secret, secret_bytes.data(), secret_bytes.size() * sizeof(unsigned char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_aad, aad_bytes.data(), aad_bytes.size() * sizeof(unsigned char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_chiphertext, ciphertext_bytes.data(), ciphertext_bytes.size() * sizeof(unsigned char), cudaMemcpyHostToDevice);

    short secret_len = static_cast<short>(secret_bytes.size());
    short aad_length = static_cast<short>(aad_bytes.size());
    short ciphertext_length = static_cast<short>(ciphertext_bytes.size());

    tls13_verify_gcm128<<<1, 1>>>(d_result, d_secret, secret_len,
                                  seq_num, d_aad, aad_length,
                                  d_chiphertext, ciphertext_length);
    cudaDeviceSynchronize();

    unsigned char h_result = 0;
    cudaMemcpy(&h_result, d_result, sizeof(unsigned char), cudaMemcpyDeviceToHost);
    bool success = (h_result != 0);

    if (!success) {
        printf("TLS 1.3 app traffic secret GCM128 match test FAIL!\n");
    } else {
        printf("TLS 1.3 app traffic secret GCM128 match test pass\n");
    }

    cudaFree(d_result);
    cudaFree(d_secret);
    cudaFree(d_aad);
    cudaFree(d_chiphertext);

    return success;
}

bool test_tls13_app_traffic_secret_scan_user_case() {
    // User provided case for scanning
    std::string app_traffic_secret = "2f04cf52fa8ce49d2a95869b55057be3541bb2a82768630a01d9558609dcd0d0";
    std::string aad_hex = "1703030057";
    std::string ciphertext_hex = "3b4aab0d4d225d605a4252ca602a8dab3572f7682afed4cbded2eebdc20abfc77951401dcb2a9f526caea93daa6ff52863363f2fcd2fa4b5235abc4b82e35b147c33fae786c9dabf6453bb4a11dcdb4fde19df89c98f16";
    uint64_t seq_num = 0;

    std::vector<unsigned char> secret_bytes = hexStringToByteArray(app_traffic_secret);
    std::vector<unsigned char> aad_bytes = hexStringToByteArray(aad_hex);
    std::vector<unsigned char> ciphertext_bytes = hexStringToByteArray(ciphertext_hex);

    // Combine AAD and Ciphertext for app_data_record
    std::vector<unsigned char> app_data_record = aad_bytes;
    app_data_record.insert(app_data_record.end(), ciphertext_bytes.begin(), ciphertext_bytes.end());

    // 1MB haystack
    uint64_t haystack_size = 1024 * 1024;
    std::vector<unsigned char> haystack(haystack_size);
    
    // Fill with random data
    for(size_t i=0; i<haystack_size; ++i) {
        haystack[i] = rand() % 256;
    }

    // Insert secret at random position.
    uint64_t secret_len = secret_bytes.size();
    uint64_t max_pos = haystack_size - secret_len;
    uint64_t secret_pos = (rand() % (max_pos - 1)) + 1;
    
    for(size_t i=0; i<secret_len; ++i) {
        haystack[secret_pos + i] = secret_bytes[i];
    }

    unsigned char client_random[32] = {0}; // All zeros

    set_memory_alignment(1);

    unsigned long long found_pos = tls_app_traffic_secret_0_gcm_128_sha_256_scan(
        haystack.data(), haystack_size,
        app_data_record.data(), app_data_record.size(),
        seq_num, client_random,
        0.0f, // entropyThreshold
        true // client
    );

    bool success = (found_pos == secret_pos);

    if (!success) {
        printf("TLS 1.3 app traffic secret scan user case test FAIL! Expected %lu, found %llu\n", secret_pos, found_pos);
    } else {
        printf("TLS 1.3 app traffic secret scan user case test pass. Found at %llu\n", found_pos);
    }

    return success;
}

bool test_tls13_server_traffic_secret_scan_user_case() {
    // User provided case for scanning server traffic secret
    std::string app_traffic_secret = "f763c8f30da44fa012cddb50eff300c8093d200788c6fe9b7baaf729ea3e1f27";
    // The whole record is AAD + Ciphertext
    std::string record_hex = "1703030039853ccc4137920434777a7e042608d1f30f759634c4b9dcdd92a5db4fcbe2b3ea2cc5a34ada070fce70234891a4f26e1293ba95513301132c6e";
    uint64_t seq_num = 1;

    std::vector<unsigned char> secret_bytes = hexStringToByteArray(app_traffic_secret);
    std::vector<unsigned char> app_data_record = hexStringToByteArray(record_hex);

    // 1MB haystack
    uint64_t haystack_size = 1024 * 1024;
    std::vector<unsigned char> haystack(haystack_size);
    
    // Fill with random data
    for(size_t i=0; i<haystack_size; ++i) {
        haystack[i] = rand() % 256;
    }

    // Insert secret at random position.
    uint64_t secret_len = secret_bytes.size();
    uint64_t max_pos = haystack_size - secret_len;
    uint64_t secret_pos = (rand() % (max_pos - 1)) + 1;
    
    for(size_t i=0; i<secret_len; ++i) {
        haystack[secret_pos + i] = secret_bytes[i];
    }

    unsigned char client_random[32] = {0}; // All zeros

    set_memory_alignment(1);

    unsigned long long found_pos = tls_app_traffic_secret_0_gcm_128_sha_256_scan(
        haystack.data(), haystack_size,
        app_data_record.data(), app_data_record.size(),
        seq_num, client_random,
        0.0f, // entropyThreshold
        false // client = false for server
    );

    bool success = (found_pos == secret_pos);

    if (!success) {
        printf("TLS 1.3 server traffic secret scan user case test FAIL! Expected %lu, found %llu\n", secret_pos, found_pos);
    } else {
        printf("TLS 1.3 server traffic secret scan user case test pass. Found at %llu\n", found_pos);
    }

    return success;
}


bool run_tests() {

    if (!test_device_availability()) return false;

    bool suc0 = run_aes128_test();
    bool suc1 = run_aes256_test();
    bool suc2 = test_sha256();
    bool suc3 = test_sha384();
    bool suc4 = test_hmac_sha256();
    bool suc5 = test_hmac_sha384();
    bool suc6 = test_tls13_key_derivation();
    bool suc7 = test_tls13_key_derivation_256();
    bool suc8 = test_tls13_app_traffic_secret_gcm128_sha256();
    bool suc9 = test_tls13_app_traffic_secret_gcm256_sha384();
    bool suc10 = test_full_gcm128();
    bool suc11 = test_tls13_app_traffic_secret_gcm128_sha256_match();
    bool suc12 = test_tls13_app_traffic_secret_scan_user_case();
    bool suc13 = test_tls13_server_traffic_secret_scan_user_case();
    bool suc14 = test_quic_app_traffic_secret_gcm128_sha256();
    return suc0 && 
           suc1 && 
           suc2 && 
           suc3 && 
           suc4 && 
           suc5 && 
           suc6 &&
           suc7 &&
           suc8 &&
           suc9 &&
           suc10 &&
           suc11 &&
           suc12 &&
           suc13 &&
           suc14;
}
