#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <cuda_runtime.h>

__device__ void cuda_sha256(const unsigned char *d_input, short input_len, unsigned char *d_digest);
