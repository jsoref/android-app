/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/e_os2.h>
#include "sm3_locl.h"

int sm3_init(SM3_CTX *c)
{
    memset(c, 0, sizeof(*c));
    c->A = SM3_A;
    c->B = SM3_B;
    c->C = SM3_C;
    c->D = SM3_D;
    c->E = SM3_E;
    c->F = SM3_F;
    c->G = SM3_G;
    c->H = SM3_H;
    return 1;
}

void sm3_block_data_order(SM3_CTX *ctx, const void *p, size_t num)
{
    const unsigned char *data = p;
    register unsigned MD32_REG_T A, B, C, D, E, F, G, H;

    unsigned MD32_REG_T W00, W01, W02, W03, W04, W05, W06, W07,
        W08, W09, W10, W11, W12, W13, W14, W15;

    for (; num--;) {

        A = ctx->A;
        B = ctx->B;
        C = ctx->C;
        D = ctx->D;
        E = ctx->E;
        F = ctx->F;
        G = ctx->G;
        H = ctx->H;

        /*
        * We have to load all message bytes immediately since SM3 reads
        * them slightly out of order.
        */
        (void)HOST_c2l(data, W00);
        (void)HOST_c2l(data, W01);
        (void)HOST_c2l(data, W02);
        (void)HOST_c2l(data, W03);
        (void)HOST_c2l(data, W04);
        (void)HOST_c2l(data, W05);
        (void)HOST_c2l(data, W06);
        (void)HOST_c2l(data, W07);
        (void)HOST_c2l(data, W08);
        (void)HOST_c2l(data, W09);
        (void)HOST_c2l(data, W10);
        (void)HOST_c2l(data, W11);
        (void)HOST_c2l(data, W12);
        (void)HOST_c2l(data, W13);
        (void)HOST_c2l(data, W14);
        (void)HOST_c2l(data, W15);

        R1(A, B, C, D, E, F, G, H, 0xFF, W00, W00 ^ W04);
        W00 = EXPAND(W00, W07, W13, W03, W10);
        R1(D, A, B, C, H, E, F, G, 0xFF, W01, W01 ^ W05);
        W01 = EXPAND(W01, W08, W14, W04, W11);
        R1(C, D, A, B, G, H, E, F, 0xFF, W02, W02 ^ W06);
        W02 = EXPAND(W02, W09, W15, W05, W12);
        R1(B, C, D, A, F, G, H, E, 0xFF, W03, W03 ^ W07);
        W03 = EXPAND(W03, W10, W00, W06, W13);
        R1(A, B, C, D, E, F, G, H, 0xFF, W04, W04 ^ W08);
        W04 = EXPAND(W04, W11, W01, W07, W14);
        R1(D, A, B, C, H, E, F, G, 0xFF, W05, W05 ^ W09);
        W05 = EXPAND(W05, W12, W02, W08, W15);
        R1(C, D, A, B, G, H, E, F, 0xFF, W06, W06 ^ W10);
        W06 = EXPAND(W06, W13, W03, W09, W00);
        R1(B, C, D, A, F, G, H, E, 0xFF, W07, W07 ^ W11);
        W07 = EXPAND(W07, W14, W04, W10, W01);
        R1(A, B, C, D, E, F, G, H, 0xFF, W08, W08 ^ W12);
        W08 = EXPAND(W08, W15, W05, W11, W02);
        R1(D, A, B, C, H, E, F, G, 0xFF, W09, W09 ^ W13);
        W09 = EXPAND(W09, W00, W06, W12, W03);
        R1(C, D, A, B, G, H, E, F, 0xFF, W10, W10 ^ W14);
        W10 = EXPAND(W10, W01, W07, W13, W04);
        R1(B, C, D, A, F, G, H, E, 0xFF, W11, W11 ^ W15);
        W11 = EXPAND(W11, W02, W08, W14, W05);
        R1(A, B, C, D, E, F, G, H, 0xFF, W12, W12 ^ W00);
        W12 = EXPAND(W12, W03, W09, W15, W06);
        R1(D, A, B, C, H, E, F, G, 0xFF, W13, W13 ^ W01);
        W13 = EXPAND(W13, W04, W10, W00, W07);
        R1(C, D, A, B, G, H, E, F, 0xFF, W14, W14 ^ W02);
        W14 = EXPAND(W14, W05, W11, W01, W08);
        R1(B, C, D, A, F, G, H, E, 0xFF, W15, W15 ^ W03);
        W15 = EXPAND(W15, W06, W12, W02, W09);
        R2(A, B, C, D, E, F, G, H, 0xFF, W00, W00 ^ W04);
        W00 = EXPAND(W00, W07, W13, W03, W10);
        R2(D, A, B, C, H, E, F, G, 0xFF, W01, W01 ^ W05);
        W01 = EXPAND(W01, W08, W14, W04, W11);
        R2(C, D, A, B, G, H, E, F, 0xFF, W02, W02 ^ W06);
        W02 = EXPAND(W02, W09, W15, W05, W12);
        R2(B, C, D, A, F, G, H, E, 0xFF, W03, W03 ^ W07);
        W03 = EXPAND(W03, W10, W00, W06, W13);
        R2(A, B, C, D, E, F, G, H, 0xFF, W04, W04 ^ W08);
        W04 = EXPAND(W04, W11, W01, W07, W14);
        R2(D, A, B, C, H, E, F, G, 0xFF, W05, W05 ^ W09);
        W05 = EXPAND(W05, W12, W02, W08, W15);
        R2(C, D, A, B, G, H, E, F, 0xFF, W06, W06 ^ W10);
        W06 = EXPAND(W06, W13, W03, W09, W00);
        R2(B, C, D, A, F, G, H, E, 0xFF, W07, W07 ^ W11);
        W07 = EXPAND(W07, W14, W04, W10, W01);
        R2(A, B, C, D, E, F, G, H, 0xFF, W08, W08 ^ W12);
        W08 = EXPAND(W08, W15, W05, W11, W02);
        R2(D, A, B, C, H, E, F, G, 0xFF, W09, W09 ^ W13);
        W09 = EXPAND(W09, W00, W06, W12, W03);
        R2(C, D, A, B, G, H, E, F, 0xFF, W10, W10 ^ W14);
        W10 = EXPAND(W10, W01, W07, W13, W04);
        R2(B, C, D, A, F, G, H, E, 0xFF, W11, W11 ^ W15);
        W11 = EXPAND(W11, W02, W08, W14, W05);
        R2(A, B, C, D, E, F, G, H, 0xFF, W12, W12 ^ W00);
        W12 = EXPAND(W12, W03, W09, W15, W06);
        R2(D, A, B, C, H, E, F, G, 0xFF, W13, W13 ^ W01);
        W13 = EXPAND(W13, W04, W10, W00, W07);
        R2(C, D, A, B, G, H, E, F, 0xFF, W14, W14 ^ W02);
        W14 = EXPAND(W14, W05, W11, W01, W08);
        R2(B, C, D, A, F, G, H, E, 0xFF, W15, W15 ^ W03);
        W15 = EXPAND(W15, W06, W12, W02, W09);
        R2(A, B, C, D, E, F, G, H, 0xFF, W00, W00 ^ W04);
        W00 = EXPAND(W00, W07, W13, W03, W10);
        R2(D, A, B, C, H, E, F, G, 0xFF, W01, W01 ^ W05);
        W01 = EXPAND(W01, W08, W14, W04, W11);
        R2(C, D, A, B, G, H, E, F, 0xFF, W02, W02 ^ W06);
        W02 = EXPAND(W02, W09, W15, W05, W12);
        R2(B, C, D, A, F, G, H, E, 0xFF, W03, W03 ^ W07);
        W03 = EXPAND(W03, W10, W00, W06, W13);
        R2(A, B, C, D, E, F, G, H, 0xFF, W04, W04 ^ W08);
        W04 = EXPAND(W04, W11, W01, W07, W14);
        R2(D, A, B, C, H, E, F, G, 0xFF, W05, W05 ^ W09);
        W05 = EXPAND(W05, W12, W02, W08, W15);
        R2(C, D, A, B, G, H, E, F, 0xFF, W06, W06 ^ W10);
        W06 = EXPAND(W06, W13, W03, W09, W00);
        R2(B, C, D, A, F, G, H, E, 0xFF, W07, W07 ^ W11);
        W07 = EXPAND(W07, W14, W04, W10, W01);
        R2(A, B, C, D, E, F, G, H, 0xFF, W08, W08 ^ W12);
        W08 = EXPAND(W08, W15, W05, W11, W02);
        R2(D, A, B, C, H, E, F, G, 0xFF, W09, W09 ^ W13);
        W09 = EXPAND(W09, W00, W06, W12, W03);
        R2(C, D, A, B, G, H, E, F, 0xFF, W10, W10 ^ W14);
        W10 = EXPAND(W10, W01, W07, W13, W04);
        R2(B, C, D, A, F, G, H, E, 0xFF, W11, W11 ^ W15);
        W11 = EXPAND(W11, W02, W08, W14, W05);
        R2(A, B, C, D, E, F, G, H, 0xFF, W12, W12 ^ W00);
        W12 = EXPAND(W12, W03, W09, W15, W06);
        R2(D, A, B, C, H, E, F, G, 0xFF, W13, W13 ^ W01);
        W13 = EXPAND(W13, W04, W10, W00, W07);
        R2(C, D, A, B, G, H, E, F, 0xFF, W14, W14 ^ W02);
        W14 = EXPAND(W14, W05, W11, W01, W08);
        R2(B, C, D, A, F, G, H, E, 0xFF, W15, W15 ^ W03);
        W15 = EXPAND(W15, W06, W12, W02, W09);
        R2(A, B, C, D, E, F, G, H, 0xFF, W00, W00 ^ W04);
        W00 = EXPAND(W00, W07, W13, W03, W10);
        R2(D, A, B, C, H, E, F, G, 0xFF, W01, W01 ^ W05);
        W01 = EXPAND(W01, W08, W14, W04, W11);
        R2(C, D, A, B, G, H, E, F, 0xFF, W02, W02 ^ W06);
        W02 = EXPAND(W02, W09, W15, W05, W12);
        R2(B, C, D, A, F, G, H, E, 0xFF, W03, W03 ^ W07);
        W03 = EXPAND(W03, W10, W00, W06, W13);
        R2(A, B, C, D, E, F, G, H, 0xFF, W04, W04 ^ W08);
        R2(D, A, B, C, H, E, F, G, 0xFF, W05, W05 ^ W09);
        R2(C, D, A, B, G, H, E, F, 0xFF, W06, W06 ^ W10);
        R2(B, C, D, A, F, G, H, E, 0xFF, W07, W07 ^ W11);
        R2(A, B, C, D, E, F, G, H, 0xFF, W08, W08 ^ W12);
        R2(D, A, B, C, H, E, F, G, 0xFF, W09, W09 ^ W13);
        R2(C, D, A, B, G, H, E, F, 0xFF, W10, W10 ^ W14);
        R2(B, C, D, A, F, G, H, E, 0xFF, W11, W11 ^ W15);
        R2(A, B, C, D, E, F, G, H, 0xFF, W12, W12 ^ W00);
        R2(D, A, B, C, H, E, F, G, 0xFF, W13, W13 ^ W01);
        R2(C, D, A, B, G, H, E, F, 0xFF, W14, W14 ^ W02);
        R2(B, C, D, A, F, G, H, E, 0xFF, W15, W15 ^ W03);

        ctx->A ^= A;
        ctx->B ^= B;
        ctx->C ^= C;
        ctx->D ^= D;
        ctx->E ^= E;
        ctx->F ^= F;
        ctx->G ^= G;
        ctx->H ^= H;
    }
}

