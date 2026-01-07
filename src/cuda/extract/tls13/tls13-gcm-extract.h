#pragma once

#include <cuda_runtime.h>
#include <cstdint>

__device__ bool cuda_match_app_traffic_secret_0_gcm128_sha256(const unsigned char* d_app_traffic_secret_0,
                                                              short app_traffic_secret_len, uint64_t seq_num,
                                                              unsigned char* d_aad, short aad_length,
                                                              unsigned char* d_chiphertext, short ciphertext_length);

__device__ bool cuda_match_app_traffic_secret_0_gcm256_sha384(const unsigned char* d_app_traffic_secret_0,
                                                              short app_traffic_secret_len, uint64_t seq_num,
                                                              unsigned char* d_aad, short aad_length,
                                                              unsigned char* d_chiphertext, short ciphertext_length);
