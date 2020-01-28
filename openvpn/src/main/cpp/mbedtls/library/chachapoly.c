/**
 * \file chachapoly.c
 *
 * \brief ChaCha20-Poly1305 AEAD construction based on RFC 7539.
 *
 *  Copyright (C) 2006-2016, ARM Limited, All Rights Reserved
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
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_CHACHAPOLY_C)

#include "mbedtls/chachapoly.h"
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

#if !defined(MBEDTLS_CHACHAPOLY_ALT)

#define CHACHAPOLY_STATE_INIT       ( 0 )
#define CHACHAPOLY_STATE_AAD        ( 1 )
#define CHACHAPOLY_STATE_CIPHERTEXT ( 2 ) /* Encrypting or decrypting */
#define CHACHAPOLY_STATE_FINISHED   ( 3 )

/**
 * \brief           Adds nul bytes to pad the AAD for Poly1305.
 *
 * \param ctx       The ChaCha20-Poly1305 context.
 */
static int chachapoly_pad_aad( mbedtls_chachapoly_context *ctx )
{
    uint32_t partial_block_len = (uint32_t) ( ctx->aad_len % 16U );
    unsigned char zeroes[15];

    if( partial_block_len == 0U )
        return( 0 );

    memset( zeroes, 0, sizeof( zeroes ) );

    return( mbedtls_poly1305_update( &ctx->poly1305_ctx,
                                     zeroes,
                                     16U - partial_block_len ) );
}

/**
 * \brief           Adds nul bytes to pad the ciphertext for Poly1305.
 *
 * \param ctx       The ChaCha20-Poly1305 context.
 */
static int chachapoly_pad_ciphertext( mbedtls_chachapoly_context *ctx )
{
    uint32_t partial_block_len = (uint32_t) ( ctx->ciphertext_len % 16U );
    unsigned char zeroes[15];

    if( partial_block_len == 0U )
        return( 0 );

    memset( zeroes, 0, sizeof( zeroes ) );
    return( mbedtls_poly1305_update( &ctx->poly1305_ctx,
                                     zeroes,
                                     16U - partial_block_len ) );
}

void mbedtls_chachapoly_init( mbedtls_chachapoly_context *ctx )
{
    if( ctx != NULL )
    {
        mbedtls_chacha20_init( &ctx->chacha20_ctx );
        mbedtls_poly1305_init( &ctx->poly1305_ctx );
        ctx->aad_len        = 0U;
        ctx->ciphertext_len = 0U;
        ctx->state          = CHACHAPOLY_STATE_INIT;
        ctx->mode           = MBEDTLS_CHACHAPOLY_ENCRYPT;
    }
}

void mbedtls_chachapoly_free( mbedtls_chachapoly_context *ctx )
{
    if( ctx != NULL )
    {
        mbedtls_chacha20_free( &ctx->chacha20_ctx );
        mbedtls_poly1305_free( &ctx->poly1305_ctx );
        ctx->aad_len        = 0U;
        ctx->ciphertext_len = 0U;
        ctx->state          = CHACHAPOLY_STATE_INIT;
        ctx->mode           = MBEDTLS_CHACHAPOLY_ENCRYPT;
    }
}

int mbedtls_chachapoly_setkey( mbedtls_chachapoly_context *ctx,
                               const unsigned char key[32] )
{
    int ret;

    if( ( ctx == NULL ) || ( key == NULL ) )
    {
        return( MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA );
    }

    ret = mbedtls_chacha20_setkey( &ctx->chacha20_ctx, key );

    return( ret );
}

int mbedtls_chachapoly_starts( mbedtls_chachapoly_context *ctx,
                               const unsigned char nonce[12],
                               mbedtls_chachapoly_mode_t mode  )
{
    int ret;
    unsigned char poly1305_key[64];

    if( ( ctx == NULL ) || ( nonce == NULL ) )
    {
        return( MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA );
    }

    /* Set counter = 0, will be update to 1 when generating Poly1305 key */
    ret = mbedtls_chacha20_starts( &ctx->chacha20_ctx, nonce, 0U );
    if( ret != 0 )
        goto cleanup;

    /* Generate the Poly1305 key by getting the ChaCha20 keystream output with
     * counter = 0.  This is the same as encrypting a buffer of zeroes.
     * Only the first 256-bits (32 bytes) of the key is used for Poly1305.
     * The other 256 bits are discarded.
     */
    memset( poly1305_key, 0, sizeof( poly1305_key ) );
    ret = mbedtls_chacha20_update( &ctx->chacha20_ctx, sizeof( poly1305_key ),
                                      poly1305_key, poly1305_key );
    if( ret != 0 )
        goto cleanup;

    ret = mbedtls_poly1305_starts( &ctx->poly1305_ctx, poly1305_key );

    if( ret == 0 )
    {
        ctx->aad_len        = 0U;
        ctx->ciphertext_len = 0U;
        ctx->state          = CHACHAPOLY_STATE_AAD;
        ctx->mode           = mode;
    }

cleanup:
    mbedtls_platform_zeroize( poly1305_key, 64U );
    return( ret );
}

int mbedtls_chachapoly_update_aad( mbedtls_chachapoly_context *ctx,
                                   const unsigned char *aad,
                                   size_t aad_len )
{
    if( ctx == NULL )
    {
        return( MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA );
    }
    else if( ( aad_len > 0U ) && ( aad == NULL ) )
    {
        /* aad pointer is allowed to be NULL if aad_len == 0 */
        return( MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA );
    }
    else if( ctx->state != CHACHAPOLY_STATE_AAD )
    {
        return( MBEDTLS_ERR_CHACHAPOLY_BAD_STATE );
    }

    ctx->aad_len += aad_len;

    return( mbedtls_poly1305_update( &ctx->poly1305_ctx, aad, aad_len ) );
}

int mbedtls_chachapoly_update( mbedtls_chachapoly_context *ctx,
                               size_t len,
                               const unsigned char *input,
                               unsigned char *output )
{
    int ret;

    if( ctx == NULL )
    {
        return( MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA );
    }
    else if( ( len > 0U ) && ( ( input == NULL ) || ( output == NULL ) ) )
    {
        /* input and output pointers are allowed to be NULL if len == 0 */
        return( MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA );
    }
    else if( ( ctx->state != CHACHAPOLY_STATE_AAD ) &&
              ( ctx->state != CHACHAPOLY_STATE_CIPHERTEXT ) )
    {
        return( MBEDTLS_ERR_CHACHAPOLY_BAD_STATE );
    }

    if( ctx->state == CHACHAPOLY_STATE_AAD )
    {
        ctx->state = CHACHAPOLY_STATE_CIPHERTEXT;

        ret = chachapoly_pad_aad( ctx );
        if( ret != 0 )
            return( ret );
    }

    ctx->ciphertext_len += len;

    if( ctx->mode == MBEDTLS_CHACHAPOLY_ENCRYPT )
    {
        ret = mbedtls_chacha20_update( &ctx->chacha20_ctx, len, input, output );
        if( ret != 0 )
            return( ret );

        ret = mbedtls_poly1305_update( &ctx->poly1305_ctx, output, len );
        if( ret != 0 )
            return( ret );
    }
    else /* DECRYPT */
    {
        ret = mbedtls_poly1305_update( &ctx->poly1305_ctx, input, len );
        if( ret != 0 )
            return( ret );

        ret = mbedtls_chacha20_update( &ctx->chacha20_ctx, len, input, output );
        if( ret != 0 )
            return( ret );
    }

    return( 0 );
}

int mbedtls_chachapoly_finish( mbedtls_chachapoly_context *ctx,
                               unsigned char mac[16] )
{
    int ret;
    unsigned char len_block[16];

    if( ( ctx == NULL ) || ( mac == NULL ) )
    {
        return( MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA );
    }
    else if( ctx->state == CHACHAPOLY_STATE_INIT )
    {
        return( MBEDTLS_ERR_CHACHAPOLY_BAD_STATE );
    }

    if( ctx->state == CHACHAPOLY_STATE_AAD )
    {
        ret = chachapoly_pad_aad( ctx );
        if( ret != 0 )
            return( ret );
    }
    else if( ctx->state == CHACHAPOLY_STATE_CIPHERTEXT )
    {
        ret = chachapoly_pad_ciphertext( ctx );
        if( ret != 0 )
            return( ret );
    }

    ctx->state = CHACHAPOLY_STATE_FINISHED;

    /* The lengths of the AAD and ciphertext are processed by
     * Poly1305 as the final 128-bit block, encoded as little-endian integers.
     */
    len_block[ 0] = (unsigned char)( ctx->aad_len       );
    len_block[ 1] = (unsigned char)( ctx->aad_len >>  8 );
    len_block[ 2] = (unsigned char)( ctx->aad_len >> 16 );
    len_block[ 3] = (unsigned char)( ctx->aad_len >> 24 );
    len_block[ 4] = (unsigned char)( ctx->aad_len >> 32 );
    len_block[ 5] = (unsigned char)( ctx->aad_len >> 40 );
    len_block[ 6] = (unsigned char)( ctx->aad_len >> 48 );
    len_block[ 7] = (unsigned char)( ctx->aad_len >> 56 );
    len_block[ 8] = (unsigned char)( ctx->ciphertext_len       );
    len_block[ 9] = (unsigned char)( ctx->ciphertext_len >>  8 );
    len_block[10] = (unsigned char)( ctx->ciphertext_len >> 16 );
    len_block[11] = (unsigned char)( ctx->ciphertext_len >> 24 );
    len_block[12] = (unsigned char)( ctx->ciphertext_len >> 32 );
    len_block[13] = (unsigned char)( ctx->ciphertext_len >> 40 );
    len_block[14] = (unsigned char)( ctx->ciphertext_len >> 48 );
    len_block[15] = (unsigned char)( ctx->ciphertext_len >> 56 );

    ret = mbedtls_poly1305_update( &ctx->poly1305_ctx, len_block, 16U );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_poly1305_finish( &ctx->poly1305_ctx, mac );

    return( ret );
}

static int chachapoly_crypt_and_tag( mbedtls_chachapoly_context *ctx,
                                     mbedtls_chachapoly_mode_t mode,
                                     size_t length,
                                     const unsigned char nonce[12],
                                     const unsigned char *aad,
                                     size_t aad_len,
                                     const unsigned char *input,
                                     unsigned char *output,
                                     unsigned char tag[16] )
{
    int ret;

    ret = mbedtls_chachapoly_starts( ctx, nonce, mode );
    if( ret != 0 )
        goto cleanup;

    ret = mbedtls_chachapoly_update_aad( ctx, aad, aad_len );
    if( ret != 0 )
        goto cleanup;

    ret = mbedtls_chachapoly_update( ctx, length, input, output );
    if( ret != 0 )
        goto cleanup;

    ret = mbedtls_chachapoly_finish( ctx, tag );

cleanup:
    return( ret );
}

int mbedtls_chachapoly_encrypt_and_tag( mbedtls_chachapoly_context *ctx,
                                        size_t length,
                                        const unsigned char nonce[12],
                                        const unsigned char *aad,
                                        size_t aad_len,
                                        const unsigned char *input,
                                        unsigned char *output,
                                        unsigned char tag[16] )
{
    return( chachapoly_crypt_and_tag( ctx, MBEDTLS_CHACHAPOLY_ENCRYPT,
                                      length, nonce, aad, aad_len,
                                      input, output, tag ) );
}

int mbedtls_chachapoly_auth_decrypt( mbedtls_chachapoly_context *ctx,
                                     size_t length,
                                     const unsigned char nonce[12],
                                     const unsigned char *aad,
                                     size_t aad_len,
                                     const unsigned char tag[16],
                                     const unsigned char *input,
                                     unsigned char *output )
{
    int ret;
    unsigned char check_tag[16];
    size_t i;
    int diff;

    if( tag == NULL )
        return( MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA );

    if( ( ret = chachapoly_crypt_and_tag( ctx,
                        MBEDTLS_CHACHAPOLY_DECRYPT, length, nonce,
                        aad, aad_len, input, output, check_tag ) ) != 0 )
    {
        return( ret );
    }

    /* Check tag in "constant-time" */
    for( diff = 0, i = 0; i < sizeof( check_tag ); i++ )
        diff |= tag[i] ^ check_tag[i];

    if( diff != 0 )
    {
        mbedtls_platform_zeroize( output, length );
        return( MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED );
    }

    return( 0 );
}

#endif /* MBEDTLS_CHACHAPOLY_ALT */

#if defined(MBEDTLS_SELF_TEST)

static const unsigned char test_key[1][32] =
{
    {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    }
};

static const unsigned char test_nonce[1][12] =
{
    {
        0xFF, 0xFF, 0xFF, 0xFF,                         /* 32-bit common part */
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF  /* 64-bit IV */
    }
};

static const unsigned char test_aad[1][12] =
{
    {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF
    }
};

static const size_t test_aad_len[1] =
{
    12U
};

static const unsigned char test_input[1][114] =
{
    {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF
    }
};

static const unsigned char test_output[1][114] =
{
    {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF
    }
};

static const size_t test_input_len[1] =
{
    114U
};

static const unsigned char test_mac[1][16] =
{
    {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    }
};

#define ASSERT( cond, args )            \
    do                                  \
    {                                   \
        if( ! ( cond ) )                \
        {                               \
            if( verbose != 0 )          \
                mbedtls_printf args;    \
                                        \
            return( -1 );               \
        }                               \
    }                                   \
    while( 0 )

int mbedtls_chachapoly_self_test( int verbose )
{
    mbedtls_chachapoly_context ctx;
    unsigned i;
    int ret;
    unsigned char output[200];
    unsigned char mac[16];

    for( i = 0U; i < 1U; i++ )
    {
        if( verbose != 0 )
            mbedtls_printf( "  ChaCha20-Poly1305 test %u ", i );

        mbedtls_chachapoly_init( &ctx );

        ret = mbedtls_chachapoly_setkey( &ctx, test_key[i] );
        ASSERT( 0 == ret, ( "setkey() error code: %i\n", ret ) );

        ret = mbedtls_chachapoly_encrypt_and_tag( &ctx,
                                                  test_input_len[i],
                                                  test_nonce[i],
                                                  test_aad[i],
                                                  test_aad_len[i],
                                                  test_input[i],
                                                  output,
                                                  mac );

        ASSERT( 0 == ret, ( "crypt_and_tag() error code: %i\n", ret ) );

        ASSERT( 0 == memcmp( output, test_output[i], test_input_len[i] ),
                ( "failure (wrong output)\n" ) );

        ASSERT( 0 == memcmp( mac, test_mac[i], 16U ),
                ( "failure (wrong MAC)\n" ) );

        mbedtls_chachapoly_free( &ctx );

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    if( verbose != 0 )
        mbedtls_printf( "\n" );

    return( 0 );
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_CHACHAPOLY_C */
