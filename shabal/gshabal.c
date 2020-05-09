#include "gshabal.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sph_shabal.h"

void HashShabal(const char *input, int inputLen, char *output)
{
    sph_shabal512_context ctx_fugue;
    char hash[64];

    sph_shabal512_init(&ctx_fugue);
    sph_shabal512(&ctx_fugue, input, inputLen);
    sph_shabal512_close(&ctx_fugue, hash);

    memcpy(output, hash, 64);
}
