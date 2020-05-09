#include "gfugue.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sph_fugue.h"

void HashFugue(const char *input, int inputLen, char *output)
{
    sph_fugue512_context ctx_fugue;
    char hash[64];

    sph_fugue512_init(&ctx_fugue);
    sph_fugue512(&ctx_fugue, input, inputLen);
    sph_fugue512_close(&ctx_fugue, hash);

    memcpy(output, hash, 64);
}
