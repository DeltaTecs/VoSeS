#include <cuda_runtime.h>

__device__ bool cuda_match_master_secret_gcm128_sha256(const unsigned char* d_master_secret, short master_secret_len,
                                        unsigned char d_client_random[32], unsigned char d_server_random[32], uint64_t seq_num,
                                        unsigned char* d_aad, short aad_length, unsigned char* d_chiphertext, short ciphertext_length);

                                        
__device__ bool cuda_match_master_secret_gcm128_sha256_plaintxt_cmp(const unsigned char* d_master_secret, short master_secret_len,
                                        unsigned char d_client_random[32], unsigned char d_server_random[32], uint64_t seq_num,
                                        unsigned char* d_plain, short d_plain_length, unsigned char* d_chiphertext, short ciphertext_length);

__device__ bool cuda_match_master_secret_gcm256_sha384(const unsigned char* d_master_secret, short master_secret_len,
                                        unsigned char d_client_random[32], unsigned char d_server_random[32], uint64_t seq_num,
                                        unsigned char* d_aad, short aad_length, unsigned char* d_chiphertext, short ciphertext_length);

__device__ bool cuda_match_master_secret_gcm256_sha384_plaintxt_cmp(const unsigned char* d_master_secret, short master_secret_len,
                                        unsigned char d_client_random[32], unsigned char d_server_random[32], uint64_t seq_num,
                                        unsigned char* d_plain, short d_plain_length, unsigned char* d_chiphertext, short ciphertext_length);
