#include <stddef.h>
#include <string.h>
#include <stdlib.h>

__device__ void cuda_hmac_sha256_128data(unsigned char *d_key, short key_len,
                 const unsigned char *d_data, short data_len,
                 unsigned char *d_hmac_result);

            