#pragma once

#include <cuda_runtime.h>
#include <cstdint>

__host__ unsigned long long tls_app_traffic_secret_0_gcm_128_sha_256_scan(const unsigned char* haystack,
                                                                   const uint64_t haystack_length,
                                                                   unsigned char* app_data_record,
                                                                   int app_data_record_length,
                                                                   uint64_t seq_num,
                                                                   unsigned char client_random[32],
                                                                   const float entropyThreshold,
                                                                   const bool client);

__host__ unsigned long long tls_app_traffic_secret_0_gcm_256_sha_384_scan(const unsigned char* haystack,
                                                                   const uint64_t haystack_length,
                                                                   unsigned char* app_data_record,
                                                                   int app_data_record_length,
                                                                   uint64_t seq_num,
                                                                   unsigned char client_random[32],
                                                                   const float entropyThreshold,
                                                                   const bool client);
