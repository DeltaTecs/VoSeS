
#include <cstdint>

__host__ bool set_memory_alignment(uint64_t alignment);

__host__ unsigned long long entropy_scan(const unsigned char* haystack, const uint64_t haystack_length, const uint64_t needle_length, const float entropyThreshold);

__host__ unsigned long long tls12_master_secret_gcm_128_sha_256_scan(const unsigned char* haystack, const uint64_t haystack_length,
                                                                   unsigned char client_random[32], unsigned char server_random[32],
                                                                   unsigned char* client_finished_msg, int client_finished_length,
                                                                   const float entropyThreshold);

__host__ unsigned long long tls12_master_secret_gcm_256_sha_384_scan(const unsigned char* haystack, const uint64_t haystack_length,
                                                                   unsigned char client_random[32], unsigned char server_random[32],
                                                                   unsigned char* client_finished_msg, int client_finished_length,
                                                                   const float entropyThreshold);

__host__ unsigned long long tls_app_traffic_secret_0_gcm_128_sha_256_scan(const unsigned char* haystack, const uint64_t haystack_length,
                                                                   unsigned char* app_data_record, int app_data_record_length,
                                                                   uint64_t seq_num, unsigned char client_random[32],
                                                                   const float entropyThreshold, const bool client);

__host__ unsigned long long tls_app_traffic_secret_0_gcm_256_sha_384_scan(const unsigned char* haystack, const uint64_t haystack_length,
                                                                   unsigned char* app_data_record, int app_data_record_length,
                                                                   uint64_t seq_num, unsigned char client_random[32],
                                                                   const float entropyThreshold, const bool client);
