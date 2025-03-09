#include "hmac-sha256.h"
#include "sha256.h"
#include "util.h"

#define BLOCK_SIZE 64          // Block size for SHA-256
#define SHA256_DIGEST_LENGTH 32

// Assume this function is provided:
// void sha256(const unsigned char *input, size_t input_len, unsigned char *digest);

void hmac_sha256(const unsigned char *key, size_t key_len,
                 const unsigned char *data, size_t data_len,
                 unsigned char *hmac_result)
{
    unsigned char key_block[BLOCK_SIZE];
    unsigned char temp_key[SHA256_DIGEST_LENGTH];

    // Step 1: Process the key
    if (key_len > BLOCK_SIZE) {
        // If key is longer than block size, hash it and use the digest
        sha256(key, key_len, temp_key);
        array_copy(key_block, temp_key, SHA256_DIGEST_LENGTH);
        array_copy(key_block + SHA256_DIGEST_LENGTH, 0, BLOCK_SIZE - SHA256_DIGEST_LENGTH);
    } else {
        // Otherwise, copy the key and pad with zeros
        array_copy(key_block, key, key_len);
        if (key_len < BLOCK_SIZE)
            array_set_zero(key_block + key_len, BLOCK_SIZE - key_len);
    }

    // Step 2: Create inner and outer padded keys
    unsigned char inner_pad[BLOCK_SIZE];
    unsigned char outer_pad[BLOCK_SIZE];
    for (int i = 0; i < BLOCK_SIZE; i++) {
        inner_pad[i] = key_block[i] ^ 0x36;
        outer_pad[i] = key_block[i] ^ 0x5c;
    }

    // Step 3: Compute inner hash = SHA256(inner_pad || data)
    unsigned char *inner_hash_input = (unsigned char*) malloc(BLOCK_SIZE + data_len);
    if (!inner_hash_input) {
        // Handle allocation error appropriately
        return;
    }
    array_copy(inner_hash_input, inner_pad, BLOCK_SIZE);
    array_copy(inner_hash_input + BLOCK_SIZE, data, data_len);

    unsigned char inner_hash[SHA256_DIGEST_LENGTH];
    sha256(inner_hash_input, BLOCK_SIZE + data_len, inner_hash);
    free(inner_hash_input);

    // Step 4: Compute outer hash = SHA256(outer_pad || inner_hash)
    unsigned char outer_hash_input[BLOCK_SIZE + SHA256_DIGEST_LENGTH];
    array_copy(outer_hash_input, outer_pad, BLOCK_SIZE);
    array_copy(outer_hash_input + BLOCK_SIZE, inner_hash, SHA256_DIGEST_LENGTH);
    sha256(outer_hash_input, BLOCK_SIZE + SHA256_DIGEST_LENGTH, hmac_result);
}