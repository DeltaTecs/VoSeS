#include <stddef.h>
#include <string.h>
#include <stdlib.h>

void hmac_sha256(const unsigned char *key, size_t key_len,
                 const unsigned char *data, size_t data_len,
                 unsigned char *hmac_result);

            