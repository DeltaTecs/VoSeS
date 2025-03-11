#include <stddef.h>
#include <string.h>
#include <stdlib.h>

__device__ void cuda_hmac_sha384_128data(const unsigned char *key, short key_len,
                 const unsigned char *data, short data_len,
                 unsigned char *hmac_result);

            