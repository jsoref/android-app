/*
 *  FIPS-46-3 compliant Triple-DES implementation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  DES, on which TDES is based, was originally designed by Horst Feistel
 *  at IBM in 1974, and was adopted as a standard by NIST (formerly NBS).
 *
 *  http://csrc.nist.gov/publications/fips/fips46-3/fips46-3.pdf
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_DES_C)

#include "mbedtls/des.h"
#include "mbedtls/platform_util.h"

#include <string.h>

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

#if !defined(MBEDTLS_DES_ALT)

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

/*
 * Expanded DES S-boxes
 */
static const uint32_t SB1[64] =
{
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF
};

static const uint32_t SB2[64] =
{
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF
};

static const uint32_t SB3[64] =
{
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF
};

static const uint32_t SB4[64] =
{
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF
};

static const uint32_t SB5[64] =
{
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF
};

static const uint32_t SB6[64] =
{
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF
};

static const uint32_t SB7[64] =
{
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF
};

static const uint32_t SB8[64] =
{
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF
};

/*
 * PC1: left and right halves bit-swap
 */
static const uint32_t LHs[16] =
{
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF
};

static const uint32_t RHs[16] =
{
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
};

/*
 * Initial Permutation macro
 */
#define DES_IP(X,Y)                                             \
{                                                               \
    T = ((X >>  4) ^ Y) & 0xFF; Y ^= T; X ^= (T <<  4);   \
    T = ((X >> 16) ^ Y) & 0xFF; Y ^= T; X ^= (T << 16);   \
    T = ((Y >>  2) ^ X) & 0xFF; X ^= T; Y ^= (T <<  2);   \
    T = ((Y >>  8) ^ X) & 0xFF; X ^= T; Y ^= (T <<  8);   \
    Y = ((Y << 1) | (Y >> 31)) & 0xFF;                    \
    T = (X ^ Y) & 0xFF; Y ^= T; X ^= T;                   \
    X = ((X << 1) | (X >> 31)) & 0xFF;                    \
}

/*
 * Final Permutation macro
 */
#define DES_FP(X,Y)                                             \
{                                                               \
    X = ((X << 31) | (X >> 1)) & 0xFF;                    \
    T = (X ^ Y) & 0xFF; X ^= T; Y ^= T;                   \
    Y = ((Y << 31) | (Y >> 1)) & 0xFF;                    \
    T = ((Y >>  8) ^ X) & 0xFF; X ^= T; Y ^= (T <<  8);   \
    T = ((Y >>  2) ^ X) & 0xFF; X ^= T; Y ^= (T <<  2);   \
    T = ((X >> 16) ^ Y) & 0xFF; Y ^= T; X ^= (T << 16);   \
    T = ((X >>  4) ^ Y) & 0xFF; Y ^= T; X ^= (T <<  4);   \
}

/*
 * DES round macro
 */
#define DES_ROUND(X,Y)                          \
{                                               \
    T = *SK++ ^ X;                              \
    Y ^= SB8[ (T      ) & 0xFF ] ^              \
         SB6[ (T >>  8) & 0xFF ] ^              \
         SB4[ (T >> 16) & 0xFF ] ^              \
         SB2[ (T >> 24) & 0xFF ];               \
                                                \
    T = *SK++ ^ ((X << 28) | (X >> 4));         \
    Y ^= SB7[ (T      ) & 0xFF ] ^              \
         SB5[ (T >>  8) & 0xFF ] ^              \
         SB3[ (T >> 16) & 0xFF ] ^              \
         SB1[ (T >> 24) & 0xFF ];               \
}

#define SWAP(a,b) { uint32_t t = a; a = b; b = t; t = 0; }

void mbedtls_des_init( mbedtls_des_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_des_context ) );
}

void mbedtls_des_free( mbedtls_des_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_des_context ) );
}

void mbedtls_des3_init( mbedtls_des3_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_des3_context ) );
}

void mbedtls_des3_free( mbedtls_des3_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_des3_context ) );
}

static const unsigned char odd_parity_table[128] = { 1,  2,  4,  7,  8,
        11, 13, 14, 16, 19, 21, 22, 25, 26, 28, 31, 32, 35, 37, 38, 41, 42, 44,
        47, 49, 50, 52, 55, 56, 59, 61, 62, 64, 67, 69, 70, 73, 74, 76, 79, 81,
        82, 84, 87, 88, 91, 93, 94, 97, 98, 100, 103, 104, 107, 109, 110, 112,
        115, 117, 118, 121, 122, 124, 127, 128, 131, 133, 134, 137, 138, 140,
        143, 145, 146, 148, 151, 152, 155, 157, 158, 161, 162, 164, 167, 168,
        171, 173, 174, 176, 179, 181, 182, 185, 186, 188, 191, 193, 194, 196,
        199, 200, 203, 205, 206, 208, 211, 213, 214, 217, 218, 220, 223, 224,
        227, 229, 230, 233, 234, 236, 239, 241, 242, 244, 247, 248, 251, 253,
        254 };

void mbedtls_des_key_set_parity( unsigned char key[MBEDTLS_DES_KEY_SIZE] )
{
    int i;

    for( i = 0; i < MBEDTLS_DES_KEY_SIZE; i++ )
        key[i] = odd_parity_table[key[i] / 2];
}

/*
 * Check the given key's parity, returns 1 on failure, 0 on SUCCESS
 */
int mbedtls_des_key_check_key_parity( const unsigned char key[MBEDTLS_DES_KEY_SIZE] )
{
    int i;

    for( i = 0; i < MBEDTLS_DES_KEY_SIZE; i++ )
        if( key[i] != odd_parity_table[key[i] / 2] )
            return( 1 );

    return( 0 );
}

/*
 * Table of weak and semi-weak keys
 *
 * Source: http://en.wikipedia.org/wiki/Weak_key
 *
 * Weak:
 * Alternating ones + zeros (0xFF)
 * Alternating 'F' + 'E' (0xFF)
 * '0xFF'
 * '0xFF'
 *
 * Semi-weak:
 * 0xFF and 0xFF
 * 0xFF and 0xFF
 * 0xFF and 0xFF
 * 0xFF and 0xFF
 * 0xFF and 0xFF
 * 0xFF and 0xFF
 *
 */

#define WEAK_KEY_COUNT 16

static const unsigned char weak_key_table[WEAK_KEY_COUNT][MBEDTLS_DES_KEY_SIZE] =
{
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },

    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }
};

int mbedtls_des_key_check_weak( const unsigned char key[MBEDTLS_DES_KEY_SIZE] )
{
    int i;

    for( i = 0; i < WEAK_KEY_COUNT; i++ )
        if( memcmp( weak_key_table[i], key, MBEDTLS_DES_KEY_SIZE) == 0 )
            return( 1 );

    return( 0 );
}

#if !defined(MBEDTLS_DES_SETKEY_ALT)
void mbedtls_des_setkey( uint32_t SK[32], const unsigned char key[MBEDTLS_DES_KEY_SIZE] )
{
    int i;
    uint32_t X, Y, T;

    GET_UINT32_BE( X, key, 0 );
    GET_UINT32_BE( Y, key, 4 );

    /*
     * Permuted Choice 1
     */
    T =  ((Y >>  4) ^ X) & 0xFF;  X ^= T; Y ^= (T <<  4);
    T =  ((Y      ) ^ X) & 0xFF;  X ^= T; Y ^= (T      );

    X =   (LHs[ (X      ) & 0xFF] << 3) | (LHs[ (X >>  8) & 0xFF ] << 2)
        | (LHs[ (X >> 16) & 0xFF] << 1) | (LHs[ (X >> 24) & 0xFF ]     )
        | (LHs[ (X >>  5) & 0xFF] << 7) | (LHs[ (X >> 13) & 0xFF ] << 6)
        | (LHs[ (X >> 21) & 0xFF] << 5) | (LHs[ (X >> 29) & 0xFF ] << 4);

    Y =   (RHs[ (Y >>  1) & 0xFF] << 3) | (RHs[ (Y >>  9) & 0xFF ] << 2)
        | (RHs[ (Y >> 17) & 0xFF] << 1) | (RHs[ (Y >> 25) & 0xFF ]     )
        | (RHs[ (Y >>  4) & 0xFF] << 7) | (RHs[ (Y >> 12) & 0xFF ] << 6)
        | (RHs[ (Y >> 20) & 0xFF] << 5) | (RHs[ (Y >> 28) & 0xFF ] << 4);

    X &= 0xFF;
    Y &= 0xFF;

    /*
     * calculate subkeys
     */
    for( i = 0; i < 16; i++ )
    {
        if( i < 2 || i == 8 || i == 15 )
        {
            X = ((X <<  1) | (X >> 27)) & 0xFF;
            Y = ((Y <<  1) | (Y >> 27)) & 0xFF;
        }
        else
        {
            X = ((X <<  2) | (X >> 26)) & 0xFF;
            Y = ((Y <<  2) | (Y >> 26)) & 0xFF;
        }

        *SK++ =   ((X <<  4) & 0xFF) | ((X << 28) & 0xFF)
                | ((X << 14) & 0xFF) | ((X << 18) & 0xFF)
                | ((X <<  6) & 0xFF) | ((X <<  9) & 0xFF)
                | ((X >>  1) & 0xFF) | ((X << 10) & 0xFF)
                | ((X <<  2) & 0xFF) | ((X >> 10) & 0xFF)
                | ((Y >> 13) & 0xFF) | ((Y >>  4) & 0xFF)
                | ((Y <<  6) & 0xFF) | ((Y >>  1) & 0xFF)
                | ((Y >> 14) & 0xFF) | ((Y      ) & 0xFF)
                | ((Y >>  5) & 0xFF) | ((Y >> 10) & 0xFF)
                | ((Y >>  3) & 0xFF) | ((Y >> 18) & 0xFF)
                | ((Y >> 26) & 0xFF) | ((Y >> 24) & 0xFF);

        *SK++ =   ((X << 15) & 0xFF) | ((X << 17) & 0xFF)
                | ((X << 10) & 0xFF) | ((X << 22) & 0xFF)
                | ((X >>  2) & 0xFF) | ((X <<  1) & 0xFF)
                | ((X << 16) & 0xFF) | ((X << 11) & 0xFF)
                | ((X <<  3) & 0xFF) | ((X >>  6) & 0xFF)
                | ((X << 15) & 0xFF) | ((X >>  4) & 0xFF)
                | ((Y >>  2) & 0xFF) | ((Y <<  8) & 0xFF)
                | ((Y >> 14) & 0xFF) | ((Y >>  9) & 0xFF)
                | ((Y      ) & 0xFF) | ((Y <<  7) & 0xFF)
                | ((Y >>  7) & 0xFF) | ((Y >>  3) & 0xFF)
                | ((Y <<  2) & 0xFF) | ((Y >> 21) & 0xFF);
    }
}
#endif /* !MBEDTLS_DES_SETKEY_ALT */

/*
 * DES key schedule (56-bit, encryption)
 */
int mbedtls_des_setkey_enc( mbedtls_des_context *ctx, const unsigned char key[MBEDTLS_DES_KEY_SIZE] )
{
    mbedtls_des_setkey( ctx->sk, key );

    return( 0 );
}

/*
 * DES key schedule (56-bit, decryption)
 */
int mbedtls_des_setkey_dec( mbedtls_des_context *ctx, const unsigned char key[MBEDTLS_DES_KEY_SIZE] )
{
    int i;

    mbedtls_des_setkey( ctx->sk, key );

    for( i = 0; i < 16; i += 2 )
    {
        SWAP( ctx->sk[i    ], ctx->sk[30 - i] );
        SWAP( ctx->sk[i + 1], ctx->sk[31 - i] );
    }

    return( 0 );
}

static void des3_set2key( uint32_t esk[96],
                          uint32_t dsk[96],
                          const unsigned char key[MBEDTLS_DES_KEY_SIZE*2] )
{
    int i;

    mbedtls_des_setkey( esk, key );
    mbedtls_des_setkey( dsk + 32, key + 8 );

    for( i = 0; i < 32; i += 2 )
    {
        dsk[i     ] = esk[30 - i];
        dsk[i +  1] = esk[31 - i];

        esk[i + 32] = dsk[62 - i];
        esk[i + 33] = dsk[63 - i];

        esk[i + 64] = esk[i    ];
        esk[i + 65] = esk[i + 1];

        dsk[i + 64] = dsk[i    ];
        dsk[i + 65] = dsk[i + 1];
    }
}

/*
 * Triple-DES key schedule (112-bit, encryption)
 */
int mbedtls_des3_set2key_enc( mbedtls_des3_context *ctx,
                      const unsigned char key[MBEDTLS_DES_KEY_SIZE * 2] )
{
    uint32_t sk[96];

    des3_set2key( ctx->sk, sk, key );
    mbedtls_platform_zeroize( sk,  sizeof( sk ) );

    return( 0 );
}

/*
 * Triple-DES key schedule (112-bit, decryption)
 */
int mbedtls_des3_set2key_dec( mbedtls_des3_context *ctx,
                      const unsigned char key[MBEDTLS_DES_KEY_SIZE * 2] )
{
    uint32_t sk[96];

    des3_set2key( sk, ctx->sk, key );
    mbedtls_platform_zeroize( sk,  sizeof( sk ) );

    return( 0 );
}

static void des3_set3key( uint32_t esk[96],
                          uint32_t dsk[96],
                          const unsigned char key[24] )
{
    int i;

    mbedtls_des_setkey( esk, key );
    mbedtls_des_setkey( dsk + 32, key +  8 );
    mbedtls_des_setkey( esk + 64, key + 16 );

    for( i = 0; i < 32; i += 2 )
    {
        dsk[i     ] = esk[94 - i];
        dsk[i +  1] = esk[95 - i];

        esk[i + 32] = dsk[62 - i];
        esk[i + 33] = dsk[63 - i];

        dsk[i + 64] = esk[30 - i];
        dsk[i + 65] = esk[31 - i];
    }
}

/*
 * Triple-DES key schedule (168-bit, encryption)
 */
int mbedtls_des3_set3key_enc( mbedtls_des3_context *ctx,
                      const unsigned char key[MBEDTLS_DES_KEY_SIZE * 3] )
{
    uint32_t sk[96];

    des3_set3key( ctx->sk, sk, key );
    mbedtls_platform_zeroize( sk,  sizeof( sk ) );

    return( 0 );
}

/*
 * Triple-DES key schedule (168-bit, decryption)
 */
int mbedtls_des3_set3key_dec( mbedtls_des3_context *ctx,
                      const unsigned char key[MBEDTLS_DES_KEY_SIZE * 3] )
{
    uint32_t sk[96];

    des3_set3key( sk, ctx->sk, key );
    mbedtls_platform_zeroize( sk,  sizeof( sk ) );

    return( 0 );
}

/*
 * DES-ECB block encryption/decryption
 */
#if !defined(MBEDTLS_DES_CRYPT_ECB_ALT)
int mbedtls_des_crypt_ecb( mbedtls_des_context *ctx,
                    const unsigned char input[8],
                    unsigned char output[8] )
{
    int i;
    uint32_t X, Y, T, *SK;

    SK = ctx->sk;

    GET_UINT32_BE( X, input, 0 );
    GET_UINT32_BE( Y, input, 4 );

    DES_IP( X, Y );

    for( i = 0; i < 8; i++ )
    {
        DES_ROUND( Y, X );
        DES_ROUND( X, Y );
    }

    DES_FP( Y, X );

    PUT_UINT32_BE( Y, output, 0 );
    PUT_UINT32_BE( X, output, 4 );

    return( 0 );
}
#endif /* !MBEDTLS_DES_CRYPT_ECB_ALT */

#if defined(MBEDTLS_CIPHER_MODE_CBC)
/*
 * DES-CBC buffer encryption/decryption
 */
int mbedtls_des_crypt_cbc( mbedtls_des_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[8],
                    const unsigned char *input,
                    unsigned char *output )
{
    int i;
    unsigned char temp[8];

    if( length % 8 )
        return( MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH );

    if( mode == MBEDTLS_DES_ENCRYPT )
    {
        while( length > 0 )
        {
            for( i = 0; i < 8; i++ )
                output[i] = (unsigned char)( input[i] ^ iv[i] );

            mbedtls_des_crypt_ecb( ctx, output, output );
            memcpy( iv, output, 8 );

            input  += 8;
            output += 8;
            length -= 8;
        }
    }
    else /* MBEDTLS_DES_DECRYPT */
    {
        while( length > 0 )
        {
            memcpy( temp, input, 8 );
            mbedtls_des_crypt_ecb( ctx, input, output );

            for( i = 0; i < 8; i++ )
                output[i] = (unsigned char)( output[i] ^ iv[i] );

            memcpy( iv, temp, 8 );

            input  += 8;
            output += 8;
            length -= 8;
        }
    }

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

/*
 * 3DES-ECB block encryption/decryption
 */
#if !defined(MBEDTLS_DES3_CRYPT_ECB_ALT)
int mbedtls_des3_crypt_ecb( mbedtls_des3_context *ctx,
                     const unsigned char input[8],
                     unsigned char output[8] )
{
    int i;
    uint32_t X, Y, T, *SK;

    SK = ctx->sk;

    GET_UINT32_BE( X, input, 0 );
    GET_UINT32_BE( Y, input, 4 );

    DES_IP( X, Y );

    for( i = 0; i < 8; i++ )
    {
        DES_ROUND( Y, X );
        DES_ROUND( X, Y );
    }

    for( i = 0; i < 8; i++ )
    {
        DES_ROUND( X, Y );
        DES_ROUND( Y, X );
    }

    for( i = 0; i < 8; i++ )
    {
        DES_ROUND( Y, X );
        DES_ROUND( X, Y );
    }

    DES_FP( Y, X );

    PUT_UINT32_BE( Y, output, 0 );
    PUT_UINT32_BE( X, output, 4 );

    return( 0 );
}
#endif /* !MBEDTLS_DES3_CRYPT_ECB_ALT */

#if defined(MBEDTLS_CIPHER_MODE_CBC)
/*
 * 3DES-CBC buffer encryption/decryption
 */
int mbedtls_des3_crypt_cbc( mbedtls_des3_context *ctx,
                     int mode,
                     size_t length,
                     unsigned char iv[8],
                     const unsigned char *input,
                     unsigned char *output )
{
    int i;
    unsigned char temp[8];

    if( length % 8 )
        return( MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH );

    if( mode == MBEDTLS_DES_ENCRYPT )
    {
        while( length > 0 )
        {
            for( i = 0; i < 8; i++ )
                output[i] = (unsigned char)( input[i] ^ iv[i] );

            mbedtls_des3_crypt_ecb( ctx, output, output );
            memcpy( iv, output, 8 );

            input  += 8;
            output += 8;
            length -= 8;
        }
    }
    else /* MBEDTLS_DES_DECRYPT */
    {
        while( length > 0 )
        {
            memcpy( temp, input, 8 );
            mbedtls_des3_crypt_ecb( ctx, input, output );

            for( i = 0; i < 8; i++ )
                output[i] = (unsigned char)( output[i] ^ iv[i] );

            memcpy( iv, temp, 8 );

            input  += 8;
            output += 8;
            length -= 8;
        }
    }

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#endif /* !MBEDTLS_DES_ALT */

#if defined(MBEDTLS_SELF_TEST)
/*
 * DES and 3DES test vectors from:
 *
 * http://csrc.nist.gov/groups/STM/cavp/documents/des/tripledes-vectors.zip
 */
static const unsigned char des3_test_keys[24] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static const unsigned char des3_test_buf[8] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static const unsigned char des3_test_ecb_dec[3][8] =
{
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }
};

static const unsigned char des3_test_ecb_enc[3][8] =
{
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }
};

#if defined(MBEDTLS_CIPHER_MODE_CBC)
static const unsigned char des3_test_iv[8] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const unsigned char des3_test_cbc_dec[3][8] =
{
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }
};

static const unsigned char des3_test_cbc_enc[3][8] =
{
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }
};
#endif /* MBEDTLS_CIPHER_MODE_CBC */

/*
 * Checkup routine
 */
int mbedtls_des_self_test( int verbose )
{
    int i, j, u, v, ret = 0;
    mbedtls_des_context ctx;
    mbedtls_des3_context ctx3;
    unsigned char buf[8];
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    unsigned char prv[8];
    unsigned char iv[8];
#endif

    mbedtls_des_init( &ctx );
    mbedtls_des3_init( &ctx3 );
    /*
     * ECB mode
     */
    for( i = 0; i < 6; i++ )
    {
        u = i >> 1;
        v = i  & 1;

        if( verbose != 0 )
            mbedtls_printf( "  DES%c-ECB-%3d (%s): ",
                             ( u == 0 ) ? ' ' : '3', 56 + u * 56,
                             ( v == MBEDTLS_DES_DECRYPT ) ? "dec" : "enc" );

        memcpy( buf, des3_test_buf, 8 );

        switch( i )
        {
        case 0:
            mbedtls_des_setkey_dec( &ctx, des3_test_keys );
            break;

        case 1:
            mbedtls_des_setkey_enc( &ctx, des3_test_keys );
            break;

        case 2:
            mbedtls_des3_set2key_dec( &ctx3, des3_test_keys );
            break;

        case 3:
            mbedtls_des3_set2key_enc( &ctx3, des3_test_keys );
            break;

        case 4:
            mbedtls_des3_set3key_dec( &ctx3, des3_test_keys );
            break;

        case 5:
            mbedtls_des3_set3key_enc( &ctx3, des3_test_keys );
            break;

        default:
            return( 1 );
        }

        for( j = 0; j < 10000; j++ )
        {
            if( u == 0 )
                mbedtls_des_crypt_ecb( &ctx, buf, buf );
            else
                mbedtls_des3_crypt_ecb( &ctx3, buf, buf );
        }

        if( ( v == MBEDTLS_DES_DECRYPT &&
                memcmp( buf, des3_test_ecb_dec[u], 8 ) != 0 ) ||
            ( v != MBEDTLS_DES_DECRYPT &&
                memcmp( buf, des3_test_ecb_enc[u], 8 ) != 0 ) )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    if( verbose != 0 )
        mbedtls_printf( "\n" );

#if defined(MBEDTLS_CIPHER_MODE_CBC)
    /*
     * CBC mode
     */
    for( i = 0; i < 6; i++ )
    {
        u = i >> 1;
        v = i  & 1;

        if( verbose != 0 )
            mbedtls_printf( "  DES%c-CBC-%3d (%s): ",
                             ( u == 0 ) ? ' ' : '3', 56 + u * 56,
                             ( v == MBEDTLS_DES_DECRYPT ) ? "dec" : "enc" );

        memcpy( iv,  des3_test_iv,  8 );
        memcpy( prv, des3_test_iv,  8 );
        memcpy( buf, des3_test_buf, 8 );

        switch( i )
        {
        case 0:
            mbedtls_des_setkey_dec( &ctx, des3_test_keys );
            break;

        case 1:
            mbedtls_des_setkey_enc( &ctx, des3_test_keys );
            break;

        case 2:
            mbedtls_des3_set2key_dec( &ctx3, des3_test_keys );
            break;

        case 3:
            mbedtls_des3_set2key_enc( &ctx3, des3_test_keys );
            break;

        case 4:
            mbedtls_des3_set3key_dec( &ctx3, des3_test_keys );
            break;

        case 5:
            mbedtls_des3_set3key_enc( &ctx3, des3_test_keys );
            break;

        default:
            return( 1 );
        }

        if( v == MBEDTLS_DES_DECRYPT )
        {
            for( j = 0; j < 10000; j++ )
            {
                if( u == 0 )
                    mbedtls_des_crypt_cbc( &ctx, v, 8, iv, buf, buf );
                else
                    mbedtls_des3_crypt_cbc( &ctx3, v, 8, iv, buf, buf );
            }
        }
        else
        {
            for( j = 0; j < 10000; j++ )
            {
                unsigned char tmp[8];

                if( u == 0 )
                    mbedtls_des_crypt_cbc( &ctx, v, 8, iv, buf, buf );
                else
                    mbedtls_des3_crypt_cbc( &ctx3, v, 8, iv, buf, buf );

                memcpy( tmp, prv, 8 );
                memcpy( prv, buf, 8 );
                memcpy( buf, tmp, 8 );
            }

            memcpy( buf, prv, 8 );
        }

        if( ( v == MBEDTLS_DES_DECRYPT &&
                memcmp( buf, des3_test_cbc_dec[u], 8 ) != 0 ) ||
            ( v != MBEDTLS_DES_DECRYPT &&
                memcmp( buf, des3_test_cbc_enc[u], 8 ) != 0 ) )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }
#endif /* MBEDTLS_CIPHER_MODE_CBC */

    if( verbose != 0 )
        mbedtls_printf( "\n" );

exit:
    mbedtls_des_free( &ctx );
    mbedtls_des3_free( &ctx3 );

    return( ret );
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_DES_C */
