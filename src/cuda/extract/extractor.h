
#include <cstdint>

__host__ unsigned long long entropy_scan(const unsigned char* haystack, const uint64_t haystack_length, const uint64_t needle_length, const float entropyThreshold);

__host__ unsigned long long tls_master_secret_gcm_128_sha_256_scan(const unsigned char* haystack, const uint64_t haystack_length,
                                                                   unsigned char client_random[32], unsigned char server_random[32],
                                                                   unsigned char* client_finished_msg, int client_finished_length,
                                                                   const float entropyThreshold);
