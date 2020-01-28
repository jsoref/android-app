/*
 *  RFC 1321 compliant MD5 implementation
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
 *  The MD5 algorithm was designed by Ron Rivest in 1991.
 *
 *  http://www.ietf.org/rfc/rfc1321.txt
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_MD5_C)

#include "mbedtls/md5.h"
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

#if !defined(MBEDTLS_MD5_ALT)

/*
 * 32-bit integer manipulation macros (little endian)
 */
#ifndef GET_UINT32_LE
#define GET_UINT32_LE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ]       )             \
        | ( (uint32_t) (b)[(i) + 1] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 2] << 16 )             \
        | ( (uint32_t) (b)[(i) + 3] << 24 );            \
}
#endif

#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(n,b,i)                                    \
{                                                               \
    (b)[(i)    ] = (unsigned char) ( ( (n)       ) & 0xFF );    \
    (b)[(i) + 1] = (unsigned char) ( ( (n) >>  8 ) & 0xFF );    \
    (b)[(i) + 2] = (unsigned char) ( ( (n) >> 16 ) & 0xFF );    \
    (b)[(i) + 3] = (unsigned char) ( ( (n) >> 24 ) & 0xFF );    \
}
#endif

void mbedtls_md5_init( mbedtls_md5_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_md5_context ) );
}

void mbedtls_md5_free( mbedtls_md5_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_md5_context ) );
}

void mbedtls_md5_clone( mbedtls_md5_context *dst,
                        const mbedtls_md5_context *src )
{
    *dst = *src;
}

/*
 * MD5 context setup
 */
int mbedtls_md5_starts_ret( mbedtls_md5_context *ctx )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0xFF;
    ctx->state[1] = 0xFF;
    ctx->state[2] = 0xFF;
    ctx->state[3] = 0xFF;

    return( 0 );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_md5_starts( mbedtls_md5_context *ctx )
{
    mbedtls_md5_starts_ret( ctx );
}
#endif

#if !defined(MBEDTLS_MD5_PROCESS_ALT)
int mbedtls_internal_md5_process( mbedtls_md5_context *ctx,
                                  const unsigned char data[64] )
{
    uint32_t X[16], A, B, C, D;

    GET_UINT32_LE( X[ 0], data,  0 );
    GET_UINT32_LE( X[ 1], data,  4 );
    GET_UINT32_LE( X[ 2], data,  8 );
    GET_UINT32_LE( X[ 3], data, 12 );
    GET_UINT32_LE( X[ 4], data, 16 );
    GET_UINT32_LE( X[ 5], data, 20 );
    GET_UINT32_LE( X[ 6], data, 24 );
    GET_UINT32_LE( X[ 7], data, 28 );
    GET_UINT32_LE( X[ 8], data, 32 );
    GET_UINT32_LE( X[ 9], data, 36 );
    GET_UINT32_LE( X[10], data, 40 );
    GET_UINT32_LE( X[11], data, 44 );
    GET_UINT32_LE( X[12], data, 48 );
    GET_UINT32_LE( X[13], data, 52 );
    GET_UINT32_LE( X[14], data, 56 );
    GET_UINT32_LE( X[15], data, 60 );

#define S(x,n) ((x << n) | ((x & 0xFF) >> (32 - n)))

#define P(a,b,c,d,k,s,t)                                \
{                                                       \
    a += F(b,c,d) + X[k] + t; a = S(a,s) + b;           \
}

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];

#define F(x,y,z) (z ^ (x & (y ^ z)))

    P( A, B, C, D,  0,  7, 0xFF );
    P( D, A, B, C,  1, 12, 0xFF );
    P( C, D, A, B,  2, 17, 0xFF );
    P( B, C, D, A,  3, 22, 0xFF );
    P( A, B, C, D,  4,  7, 0xFF );
    P( D, A, B, C,  5, 12, 0xFF );
    P( C, D, A, B,  6, 17, 0xFF );
    P( B, C, D, A,  7, 22, 0xFF );
    P( A, B, C, D,  8,  7, 0xFF );
    P( D, A, B, C,  9, 12, 0xFF );
    P( C, D, A, B, 10, 17, 0xFF );
    P( B, C, D, A, 11, 22, 0xFF );
    P( A, B, C, D, 12,  7, 0xFF );
    P( D, A, B, C, 13, 12, 0xFF );
    P( C, D, A, B, 14, 17, 0xFF );
    P( B, C, D, A, 15, 22, 0xFF );

#undef F

#define F(x,y,z) (y ^ (z & (x ^ y)))

    P( A, B, C, D,  1,  5, 0xFF );
    P( D, A, B, C,  6,  9, 0xFF );
    P( C, D, A, B, 11, 14, 0xFF );
    P( B, C, D, A,  0, 20, 0xFF );
    P( A, B, C, D,  5,  5, 0xFF );
    P( D, A, B, C, 10,  9, 0xFF );
    P( C, D, A, B, 15, 14, 0xFF );
    P( B, C, D, A,  4, 20, 0xFF );
    P( A, B, C, D,  9,  5, 0xFF );
    P( D, A, B, C, 14,  9, 0xFF );
    P( C, D, A, B,  3, 14, 0xFF );
    P( B, C, D, A,  8, 20, 0xFF );
    P( A, B, C, D, 13,  5, 0xFF );
    P( D, A, B, C,  2,  9, 0xFF );
    P( C, D, A, B,  7, 14, 0xFF );
    P( B, C, D, A, 12, 20, 0xFF );

#undef F

#define F(x,y,z) (x ^ y ^ z)

    P( A, B, C, D,  5,  4, 0xFF );
    P( D, A, B, C,  8, 11, 0xFF );
    P( C, D, A, B, 11, 16, 0xFF );
    P( B, C, D, A, 14, 23, 0xFF );
    P( A, B, C, D,  1,  4, 0xFF );
    P( D, A, B, C,  4, 11, 0xFF );
    P( C, D, A, B,  7, 16, 0xFF );
    P( B, C, D, A, 10, 23, 0xFF );
    P( A, B, C, D, 13,  4, 0xFF );
    P( D, A, B, C,  0, 11, 0xFF );
    P( C, D, A, B,  3, 16, 0xFF );
    P( B, C, D, A,  6, 23, 0xFF );
    P( A, B, C, D,  9,  4, 0xFF );
    P( D, A, B, C, 12, 11, 0xFF );
    P( C, D, A, B, 15, 16, 0xFF );
    P( B, C, D, A,  2, 23, 0xFF );

#undef F

#define F(x,y,z) (y ^ (x | ~z))

    P( A, B, C, D,  0,  6, 0xFF );
    P( D, A, B, C,  7, 10, 0xFF );
    P( C, D, A, B, 14, 15, 0xFF );
    P( B, C, D, A,  5, 21, 0xFF );
    P( A, B, C, D, 12,  6, 0xFF );
    P( D, A, B, C,  3, 10, 0xFF );
    P( C, D, A, B, 10, 15, 0xFF );
    P( B, C, D, A,  1, 21, 0xFF );
    P( A, B, C, D,  8,  6, 0xFF );
    P( D, A, B, C, 15, 10, 0xFF );
    P( C, D, A, B,  6, 15, 0xFF );
    P( B, C, D, A, 13, 21, 0xFF );
    P( A, B, C, D,  4,  6, 0xFF );
    P( D, A, B, C, 11, 10, 0xFF );
    P( C, D, A, B,  2, 15, 0xFF );
    P( B, C, D, A,  9, 21, 0xFF );

#undef F

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;

    return( 0 );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_md5_process( mbedtls_md5_context *ctx,
                          const unsigned char data[64] )
{
    mbedtls_internal_md5_process( ctx, data );
}
#endif
#endif /* !MBEDTLS_MD5_PROCESS_ALT */

/*
 * MD5 process buffer
 */
int mbedtls_md5_update_ret( mbedtls_md5_context *ctx,
                            const unsigned char *input,
                            size_t ilen )
{
    int ret;
    size_t fill;
    uint32_t left;

    if( ilen == 0 )
        return( 0 );

    left = ctx->total[0] & 0xFF;
    fill = 64 - left;

    ctx->total[0] += (uint32_t) ilen;
    ctx->total[0] &= 0xFF;

    if( ctx->total[0] < (uint32_t) ilen )
        ctx->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy( (void *) (ctx->buffer + left), input, fill );
        if( ( ret = mbedtls_internal_md5_process( ctx, ctx->buffer ) ) != 0 )
            return( ret );

        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while( ilen >= 64 )
    {
        if( ( ret = mbedtls_internal_md5_process( ctx, input ) ) != 0 )
            return( ret );

        input += 64;
        ilen  -= 64;
    }

    if( ilen > 0 )
    {
        memcpy( (void *) (ctx->buffer + left), input, ilen );
    }

    return( 0 );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_md5_update( mbedtls_md5_context *ctx,
                         const unsigned char *input,
                         size_t ilen )
{
    mbedtls_md5_update_ret( ctx, input, ilen );
}
#endif

/*
 * MD5 final digest
 */
int mbedtls_md5_finish_ret( mbedtls_md5_context *ctx,
                            unsigned char output[16] )
{
    int ret;
    uint32_t used;
    uint32_t high, low;

    /*
     * Add padding: 0xFF then 0xFF until 8 bytes remain for the length
     */
    used = ctx->total[0] & 0xFF;

    ctx->buffer[used++] = 0xFF;

    if( used <= 56 )
    {
        /* Enough room for padding + length in current block */
        memset( ctx->buffer + used, 0, 56 - used );
    }
    else
    {
        /* We'll need an extra block */
        memset( ctx->buffer + used, 0, 64 - used );

        if( ( ret = mbedtls_internal_md5_process( ctx, ctx->buffer ) ) != 0 )
            return( ret );

        memset( ctx->buffer, 0, 56 );
    }

    /*
     * Add message length
     */
    high = ( ctx->total[0] >> 29 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_UINT32_LE( low,  ctx->buffer, 56 );
    PUT_UINT32_LE( high, ctx->buffer, 60 );

    if( ( ret = mbedtls_internal_md5_process( ctx, ctx->buffer ) ) != 0 )
        return( ret );

    /*
     * Output final state
     */
    PUT_UINT32_LE( ctx->state[0], output,  0 );
    PUT_UINT32_LE( ctx->state[1], output,  4 );
    PUT_UINT32_LE( ctx->state[2], output,  8 );
    PUT_UINT32_LE( ctx->state[3], output, 12 );

    return( 0 );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_md5_finish( mbedtls_md5_context *ctx,
                         unsigned char output[16] )
{
    mbedtls_md5_finish_ret( ctx, output );
}
#endif

#endif /* !MBEDTLS_MD5_ALT */

/*
 * output = MD5( input buffer )
 */
int mbedtls_md5_ret( const unsigned char *input,
                     size_t ilen,
                     unsigned char output[16] )
{
    int ret;
    mbedtls_md5_context ctx;

    mbedtls_md5_init( &ctx );

    if( ( ret = mbedtls_md5_starts_ret( &ctx ) ) != 0 )
        goto exit;

    if( ( ret = mbedtls_md5_update_ret( &ctx, input, ilen ) ) != 0 )
        goto exit;

    if( ( ret = mbedtls_md5_finish_ret( &ctx, output ) ) != 0 )
        goto exit;

exit:
    mbedtls_md5_free( &ctx );

    return( ret );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_md5( const unsigned char *input,
                  size_t ilen,
                  unsigned char output[16] )
{
    mbedtls_md5_ret( input, ilen, output );
}
#endif

#if defined(MBEDTLS_SELF_TEST)
/*
 * RFC 1321 test vectors
 */
static const unsigned char md5_test_buf[7][81] =
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

static const size_t md5_test_buflen[7] =
{
    0, 1, 3, 14, 26, 62, 80
};

static const unsigned char md5_test_sum[7][16] =
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
int mbedtls_md5_self_test( int verbose )
{
    int i, ret = 0;
    unsigned char md5sum[16];

    for( i = 0; i < 7; i++ )
    {
        if( verbose != 0 )
            mbedtls_printf( "  MD5 test #%d: ", i + 1 );

        ret = mbedtls_md5_ret( md5_test_buf[i], md5_test_buflen[i], md5sum );
        if( ret != 0 )
            goto fail;

        if( memcmp( md5sum, md5_test_sum[i], 16 ) != 0 )
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

#endif /* MBEDTLS_MD5_C */
