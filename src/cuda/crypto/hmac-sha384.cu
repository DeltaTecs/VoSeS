#include "hmac-sha384.h"
#include "sha384.h"
#include "../util.h"

#define BLOCK_SIZE 128         // Block size for SHA-384 (and SHA-512)
#define SHA384_DIGEST_LENGTH 48

// Assume this function is provided:
// void sha384(const unsigned char *input, size_t input_len, unsigned char *digest);
// max data length 128 bytes
__device__ void cuda_hmac_sha384_128data(const unsigned char *key, short key_len,
                 const unsigned char *data, short data_len,
                 unsigned char *hmac_result) {
    unsigned char key_block[BLOCK_SIZE];
    unsigned char temp_key[SHA384_DIGEST_LENGTH];

    if (data_len > 128) {
        printf("ERROR hmac_sha256 data given is longer than 128 byte maximum\n");
        return;
    }
    // Step 1: Process the key
    if (key_len > BLOCK_SIZE) {
        // If key is longer than block size, hash it and use the digest.
        cuda_sha384(key, key_len, temp_key);
        cuda_array_copy(key_block, temp_key, SHA384_DIGEST_LENGTH);
        cuda_array_set_zero(key_block + SHA384_DIGEST_LENGTH, BLOCK_SIZE - SHA384_DIGEST_LENGTH);
    } else {
        // Otherwise, copy the key and pad with zeros.
        cuda_array_copy(key_block, key, key_len);
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

    // Step 3: Compute inner hash = SHA384(inner_pad || data)
    // Allocate memory for the concatenated inner_pad and data.
    unsigned char inner_hash_input[64 + 128];
    cuda_array_copy(inner_hash_input, inner_pad, BLOCK_SIZE);
    cuda_array_copy(inner_hash_input + BLOCK_SIZE, data, data_len);

    unsigned char inner_hash[SHA384_DIGEST_LENGTH];
    cuda_sha384(inner_hash_input, BLOCK_SIZE + data_len, inner_hash);

    // Step 4: Compute outer hash = SHA384(outer_pad || inner_hash)
    unsigned char outer_hash_input[BLOCK_SIZE + SHA384_DIGEST_LENGTH];
    cuda_array_copy(outer_hash_input, outer_pad, BLOCK_SIZE);
    cuda_array_copy(outer_hash_input + BLOCK_SIZE, inner_hash, SHA384_DIGEST_LENGTH);
    cuda_sha384(outer_hash_input, BLOCK_SIZE + SHA384_DIGEST_LENGTH, hmac_result);
}