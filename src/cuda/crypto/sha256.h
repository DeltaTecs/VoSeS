#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <cuda_runtime.h>

__device__ void cuda_sha256_2blocks(const unsigned char *input, int input_len, unsigned char *digest);
