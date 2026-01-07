#pragma once

#include <cuda_runtime.h>
#include <cstdint>

__device__ bool cuda_match_quic_app_traffic_secret_0_gcm128_sha256(const unsigned char* d_app_traffic_secret_0,
                                                                   short app_traffic_secret_len,
                                                                   const unsigned char* d_packet,
                                                                   short packet_length, short pn_offset);

__device__ bool cuda_match_quic_app_traffic_secret_0_gcm256_sha384(const unsigned char* d_app_traffic_secret_0,
                                                                   short app_traffic_secret_len,
                                                                   const unsigned char* d_packet,
                                                                   short packet_length, short pn_offset);
