#include "hmac-sha256.h"
#include "sha256.h"
#include "../cuda_util.h"

#define BLOCK_SIZE 64          // Block size for SHA-256
#define SHA256_DIGEST_LENGTH 32

// Assume this function is provided:
// void sha256(const unsigned char *input, size_t input_len, unsigned char *digest);
// max data length 128 bytes
__device__ void cuda_hmac_sha256_128data(const unsigned char *d_key, short key_len,
                 const unsigned char *d_data, short data_len,
                 unsigned char *d_hmac_result)
{
    unsigned char key_block[BLOCK_SIZE];
    unsigned char temp_key[SHA256_DIGEST_LENGTH];

    if (data_len > 128) {
        printf("ERROR hmac_sha256 data given is longer than 128 byte maximum\n");
        return;
    }

    // Step 1: Process the key
    if (key_len > BLOCK_SIZE) {
        // If key is longer than block size, hash it and use the digest
        cuda_sha256(d_key, key_len, temp_key);
        cuda_array_copy(key_block, temp_key, SHA256_DIGEST_LENGTH);
        cuda_array_copy(key_block + SHA256_DIGEST_LENGTH, 0, BLOCK_SIZE - SHA256_DIGEST_LENGTH);
    } else {
        // Otherwise, copy the key and pad with zeros
        cuda_array_copy(key_block, d_key, key_len);
        if (key_len < BLOCK_SIZE)
            cuda_array_set_zero(key_block + key_len, BLOCK_SIZE - key_len);
    }

    // Step 2: Create inner and outer padded keys
    unsigned char inner_pad[BLOCK_SIZE];
    unsigned char outer_pad[BLOCK_SIZE];
    for (int i = 0; i < BLOCK_SIZE; i++) {
        inner_pad[i] = key_block[i] ^ 0x36;
        outer_pad[i] = key_block[i] ^ 0x5c;
    }

    // Step 3: Compute inner hash = SHA256(inner_pad || data)
    unsigned char inner_hash_input[64 + 128];
    cuda_array_copy(inner_hash_input, inner_pad, BLOCK_SIZE);
    cuda_array_copy(inner_hash_input + BLOCK_SIZE, d_data, data_len);

    unsigned char inner_hash[SHA256_DIGEST_LENGTH];
    cuda_sha256(inner_hash_input, BLOCK_SIZE + data_len, inner_hash);

    // Step 4: Compute outer hash = SHA256(outer_pad || inner_hash)
    unsigned char outer_hash_input[BLOCK_SIZE + SHA256_DIGEST_LENGTH];
    cuda_array_copy(outer_hash_input, outer_pad, BLOCK_SIZE);
    cuda_array_copy(outer_hash_input + BLOCK_SIZE, inner_hash, SHA256_DIGEST_LENGTH);
    cuda_sha256(outer_hash_input, BLOCK_SIZE + SHA256_DIGEST_LENGTH, d_hmac_result);
}