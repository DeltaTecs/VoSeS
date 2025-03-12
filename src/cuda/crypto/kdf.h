#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

// This function implements the TLS 1.2 key expansion for AES-256-GCM.
// It derives a 72-byte key block from the master secret, server random, and client random,
// then partitions it as follows:
//   d_client_write_key: first 32 bytes
//   d_server_write_key: next 32 bytes
//   d_client_iv: next 4 bytes
//   d_server_iv: next 4 bytes
__device__ void cuda_derive_tls12_keys_256(const unsigned char *d_master_secret, short d_master_secret_len,
                         const unsigned char d_client_random[32], const unsigned char d_server_random[32],
                         unsigned char *d_client_write_key, unsigned char *d_server_write_key,
                         unsigned char *d_client_iv, unsigned char *d_server_iv);

// This function implements the TLS 1.2 key expansion for AES-128-GCM.
// It derives a 40-byte key block from the master secret, server random, and client random,
// then partitions it as follows:
//   d_client_write_key: first 16 bytes
//   d_server_write_key: next 16 bytes
//   d_client_iv: next 4 bytes
//   d_server_iv: next 4 bytes
__device__ void cuda_derive_tls12_keys_128(const unsigned char *d_master_secret, short d_master_secret_len,
                         const unsigned char d_client_random[32], const unsigned char d_server_random[32],
                         unsigned char *d_client_write_key, unsigned char *d_server_write_key,
                         unsigned char *d_client_iv, unsigned char *d_server_iv);


/* Build the 12-byte AES-GCM d_nonce for a TLS record.
 * Parameters:
 *   seq_num  - the 64-bit record sequence number
 *   d_fixed_iv - the 4-byte fixed IV (d_client_iv or d_server_iv)
 *   d_nonce    - output buffer (must be at least 12 bytes)
 */
__device__ void cuda_build_tls12_aes_gcm_nonce(uint64_t seq_num, const unsigned char d_fixed_iv[4], unsigned char d_nonce[12]);