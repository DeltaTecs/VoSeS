#pragma once

#include <cuda_runtime.h>
#include <cstdint>

__host__ unsigned long long tls12_master_secret_gcm_128_sha_256_scan(const unsigned char* haystack,
                                                                     const uint64_t haystack_length,
                                                                     unsigned char client_random[32],
                                                                     unsigned char server_random[32],
                                                                     unsigned char* client_finished_msg,
                                                                     int client_finished_length,
                                                                     const float entropyThreshold);

__host__ unsigned long long tls12_master_secret_gcm_256_sha_384_scan(const unsigned char* haystack,
                                                                     const uint64_t haystack_length,
                                                                     unsigned char client_random[32],
                                                                     unsigned char server_random[32],
                                                                     unsigned char* client_finished_msg,
                                                                     int client_finished_length,
                                                                     const float entropyThreshold);
