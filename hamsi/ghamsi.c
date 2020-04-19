#ifndef VERGE_CRYPTO_POW_HAMSI_H
#define VERGE_CRYPTO_POW_HAMSI_H

#include "ghamsi.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sph_hamsi.h"


void HashHamsi(const char *input, int inputLen, char *output)
{
    sph_hamsi512_context ctx_hamsi;
    uint32_t hash[16];

    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512 (&ctx_hamsi, input, inputLen);
    sph_hamsi512_close(&ctx_hamsi, hash);

    memcpy(output, hash, 64);
}

#endif // VERGE_CRYPTO_POW_HAMSI_H
