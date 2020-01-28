/*
 *  RFC 1115/1319 compliant MD2 implementation
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
 *  The MD2 algorithm was designed by Ron Rivest in 1989.
 *
 *  http://www.ietf.org/rfc/rfc1115.txt
 *  http://www.ietf.org/rfc/rfc1319.txt
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_MD2_C)

#include "mbedtls/md2.h"
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

#if !defined(MBEDTLS_MD2_ALT)

static const unsigned char PI_SUBST[256] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

void mbedtls_md2_init( mbedtls_md2_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_md2_context ) );
}

void mbedtls_md2_free( mbedtls_md2_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_md2_context ) );
}

void mbedtls_md2_clone( mbedtls_md2_context *dst,
                        const mbedtls_md2_context *src )
{
    *dst = *src;
}

/*
 * MD2 context setup
 */
int mbedtls_md2_starts_ret( mbedtls_md2_context *ctx )
{
    memset( ctx->cksum, 0, 16 );
    memset( ctx->state, 0, 46 );
    memset( ctx->buffer, 0, 16 );
    ctx->left = 0;

    return( 0 );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_md2_starts( mbedtls_md2_context *ctx )
{
    mbedtls_md2_starts_ret( ctx );
}
#endif

#if !defined(MBEDTLS_MD2_PROCESS_ALT)
int mbedtls_internal_md2_process( mbedtls_md2_context *ctx )
{
    int i, j;
    unsigned char t = 0;

    for( i = 0; i < 16; i++ )
    {
        ctx->state[i + 16] = ctx->buffer[i];
        ctx->state[i + 32] =
            (unsigned char)( ctx->buffer[i] ^ ctx->state[i]);
    }

    for( i = 0; i < 18; i++ )
    {
        for( j = 0; j < 48; j++ )
        {
            ctx->state[j] = (unsigned char)
               ( ctx->state[j] ^ PI_SUBST[t] );
            t  = ctx->state[j];
        }

        t = (unsigned char)( t + i );
    }

    t = ctx->cksum[15];

    for( i = 0; i < 16; i++ )
    {
        ctx->cksum[i] = (unsigned char)
           ( ctx->cksum[i] ^ PI_SUBST[ctx->buffer[i] ^ t] );
        t  = ctx->cksum[i];
    }

    return( 0 );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_md2_process( mbedtls_md2_context *ctx )
{
    mbedtls_internal_md2_process( ctx );
}
#endif
#endif /* !MBEDTLS_MD2_PROCESS_ALT */

/*
 * MD2 process buffer
 */
int mbedtls_md2_update_ret( mbedtls_md2_context *ctx,
                            const unsigned char *input,
                            size_t ilen )
{
    int ret;
    size_t fill;

    while( ilen > 0 )
    {
        if( ilen > 16 - ctx->left )
            fill = 16 - ctx->left;
        else
            fill = ilen;

        memcpy( ctx->buffer + ctx->left, input, fill );

        ctx->left += fill;
        input += fill;
        ilen  -= fill;

        if( ctx->left == 16 )
        {
            ctx->left = 0;
            if( ( ret = mbedtls_internal_md2_process( ctx ) ) != 0 )
                return( ret );
        }
    }

    return( 0 );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_md2_update( mbedtls_md2_context *ctx,
                         const unsigned char *input,
                         size_t ilen )
{
    mbedtls_md2_update_ret( ctx, input, ilen );
}
#endif

/*
 * MD2 final digest
 */
int mbedtls_md2_finish_ret( mbedtls_md2_context *ctx,
                            unsigned char output[16] )
{
    int ret;
    size_t i;
    unsigned char x;

    x = (unsigned char)( 16 - ctx->left );

    for( i = ctx->left; i < 16; i++ )
        ctx->buffer[i] = x;

    if( ( ret = mbedtls_internal_md2_process( ctx ) ) != 0 )
        return( ret );

    memcpy( ctx->buffer, ctx->cksum, 16 );
    if( ( ret = mbedtls_internal_md2_process( ctx ) ) != 0 )
        return( ret );

    memcpy( output, ctx->state, 16 );

    return( 0 );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_md2_finish( mbedtls_md2_context *ctx,
                         unsigned char output[16] )
{
    mbedtls_md2_finish_ret( ctx, output );
}
#endif

#endif /* !MBEDTLS_MD2_ALT */

/*
 * output = MD2( input buffer )
 */
int mbedtls_md2_ret( const unsigned char *input,
                     size_t ilen,
                     unsigned char output[16] )
{
    int ret;
    mbedtls_md2_context ctx;

    mbedtls_md2_init( &ctx );

    if( ( ret = mbedtls_md2_starts_ret( &ctx ) ) != 0 )
        goto exit;

    if( ( ret = mbedtls_md2_update_ret( &ctx, input, ilen ) ) != 0 )
        goto exit;

    if( ( ret = mbedtls_md2_finish_ret( &ctx, output ) ) != 0 )
        goto exit;

exit:
    mbedtls_md2_free( &ctx );

    return( ret );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_md2( const unsigned char *input,
                  size_t ilen,
                  unsigned char output[16] )
{
    mbedtls_md2_ret( input, ilen, output );
}
#endif

#if defined(MBEDTLS_SELF_TEST)

/*
 * RFC 1319 test vectors
 */
static const unsigned char md2_test_str[7][81] =
{
    { "" },
    { "a" },
    { "abc" },
    { "message digest" },
    { "abcdefghijklmnopqrstuvwxyz" },
    { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" },
    { "12345678901234567890123456789012345678901234567890123456789012"
      "345678901234567890" }
};

static const size_t md2_test_strlen[7] =
{
    0, 1, 3, 14, 26, 62, 80
};

static const unsigned char md2_test_sum[7][16] =
{
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }
};

/*
 * Checkup routine
 */
int mbedtls_md2_self_test( int verbose )
{
    int i, ret = 0;
    unsigned char md2sum[16];

    for( i = 0; i < 7; i++ )
    {
        if( verbose != 0 )
            mbedtls_printf( "  MD2 test #%d: ", i + 1 );

        ret = mbedtls_md2_ret( md2_test_str[i], md2_test_strlen[i], md2sum );
        if( ret != 0 )
            goto fail;

        if( memcmp( md2sum, md2_test_sum[i], 16 ) != 0 )
        {
            ret = 1;
            goto fail;
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    if( verbose != 0 )
        mbedtls_printf( "\n" );

    return( 0 );

fail:
    if( verbose != 0 )
        mbedtls_printf( "failed\n" );

    return( ret );
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_MD2_C */
