/*
 *  ARIA implementation
 *
 *  Copyright (C) 2006-2017, ARM Limited, All Rights Reserved
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
 * This implementation is based on the following standards:
 * [1] http://210.104.33.10/ARIA/doc/ARIA-specification-e.pdf
 * [2] https://tools.ietf.org/html/rfc5794
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ARIA_C)

#include "mbedtls/aria.h"

#include <string.h>

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

#if !defined(MBEDTLS_ARIA_ALT)

#include "mbedtls/platform_util.h"

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

/*
 * 32-bit integer manipulation macros (little endian)
 */
#ifndef GET_UINT32_LE
#define GET_UINT32_LE( n, b, i )                \
{                                               \
    (n) = ( (uint32_t) (b)[(i)    ]       )     \
        | ( (uint32_t) (b)[(i) + 1] <<  8 )     \
        | ( (uint32_t) (b)[(i) + 2] << 16 )     \
        | ( (uint32_t) (b)[(i) + 3] << 24 );    \
}
#endif

#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE( n, b, i )                                \
{                                                               \
    (b)[(i)    ] = (unsigned char) ( ( (n)       ) & 0xFF );    \
    (b)[(i) + 1] = (unsigned char) ( ( (n) >>  8 ) & 0xFF );    \
    (b)[(i) + 2] = (unsigned char) ( ( (n) >> 16 ) & 0xFF );    \
    (b)[(i) + 3] = (unsigned char) ( ( (n) >> 24 ) & 0xFF );    \
}
#endif

/*
 * modify byte order: ( A B C D ) -> ( B A D C ), i.e. swap pairs of bytes
 *
 * This is submatrix P1 in [1] Appendix B.1
 *
 * Common compilers fail to translate this to minimal number of instructions,
 * so let's provide asm versions for common platforms with C fallback.
 */
#if defined(MBEDTLS_HAVE_ASM)
#if defined(__arm__) /* rev16 available from v6 up */
/* armcc5 --gnu defines __GNUC__ but doesn't support GNU's extended asm */
#if defined(__GNUC__) && \
    ( !defined(__ARMCC_VERSION) || __ARMCC_VERSION >= 6000000 ) && \
    __ARM_ARCH >= 6
static inline uint32_t aria_p1( uint32_t x )
{
    uint32_t r;
    __asm( "rev16 %0, %1" : "=l" (r) : "l" (x) );
    return( r );
}
#define ARIA_P1 aria_p1
#elif defined(__ARMCC_VERSION) && __ARMCC_VERSION < 6000000 && \
    ( __TARGET_ARCH_ARM >= 6 || __TARGET_ARCH_THUMB >= 3 )
static inline uint32_t aria_p1( uint32_t x )
{
    uint32_t r;
    __asm( "rev16 r, x" );
    return( r );
}
#define ARIA_P1 aria_p1
#endif
#endif /* arm */
#if defined(__GNUC__) && \
    defined(__i386__) || defined(__amd64__) || defined( __x86_64__)
/* I couldn't find an Intel equivalent of rev16, so two instructions */
#define ARIA_P1(x) ARIA_P2( ARIA_P3( x ) )
#endif /* x86 gnuc */
#endif /* MBEDTLS_HAVE_ASM && GNUC */
#if !defined(ARIA_P1)
#define ARIA_P1(x) ((((x) >> 8) & 0xFF) ^ (((x) & 0xFF) << 8))
#endif

/*
 * modify byte order: ( A B C D ) -> ( C D A B ), i.e. rotate by 16 bits
 *
 * This is submatrix P2 in [1] Appendix B.1
 *
 * Common compilers will translate this to a single instruction.
 */
#define ARIA_P2(x) (((x) >> 16) ^ ((x) << 16))

/*
 * modify byte order: ( A B C D ) -> ( D C B A ), i.e. change endianness
 *
 * This is submatrix P3 in [1] Appendix B.1
 *
 * Some compilers fail to translate this to a single instruction,
 * so let's provide asm versions for common platforms with C fallback.
 */
#if defined(MBEDTLS_HAVE_ASM)
#if defined(__arm__) /* rev available from v6 up */
/* armcc5 --gnu defines __GNUC__ but doesn't support GNU's extended asm */
#if defined(__GNUC__) && \
    ( !defined(__ARMCC_VERSION) || __ARMCC_VERSION >= 6000000 ) && \
    __ARM_ARCH >= 6
static inline uint32_t aria_p3( uint32_t x )
{
    uint32_t r;
    __asm( "rev %0, %1" : "=l" (r) : "l" (x) );
    return( r );
}
#define ARIA_P3 aria_p3
#elif defined(__ARMCC_VERSION) && __ARMCC_VERSION < 6000000 && \
    ( __TARGET_ARCH_ARM >= 6 || __TARGET_ARCH_THUMB >= 3 )
static inline uint32_t aria_p3( uint32_t x )
{
    uint32_t r;
    __asm( "rev r, x" );
    return( r );
}
#define ARIA_P3 aria_p3
#endif
#endif /* arm */
#if defined(__GNUC__) && \
    defined(__i386__) || defined(__amd64__) || defined( __x86_64__)
static inline uint32_t aria_p3( uint32_t x )
{
    __asm( "bswap %0" : "=r" (x) : "0" (x) );
    return( x );
}
#define ARIA_P3 aria_p3
#endif /* x86 gnuc */
#endif /* MBEDTLS_HAVE_ASM && GNUC */
#if !defined(ARIA_P3)
#define ARIA_P3(x) ARIA_P2( ARIA_P1 ( x ) )
#endif

/*
 * ARIA Affine Transform
 * (a, b, c, d) = state in/out
 *
 * If we denote the first byte of input by 0, ..., the last byte by f,
 * then inputs are: a = 0123, b = 4567, c = 89ab, d = cdef.
 *
 * Reading [1] 2.4 or [2] 2.4.3 in columns and performing simple
 * rearrangements on adjacent pairs, output is:
 *
 * a = 3210 + 4545 + 6767 + 88aa + 99bb + dccd + effe
 *   = 3210 + 4567 + 6745 + 89ab + 98ba + dcfe + efcd
 * b = 0101 + 2323 + 5476 + 8998 + baab + eecc + ffdd
 *   = 0123 + 2301 + 5476 + 89ab + ba98 + efcd + fedc
 * c = 0022 + 1133 + 4554 + 7667 + ab89 + dcdc + fefe
 *   = 0123 + 1032 + 4567 + 7654 + ab89 + dcfe + fedc
 * d = 1001 + 2332 + 6644 + 7755 + 9898 + baba + cdef
 *   = 1032 + 2301 + 6745 + 7654 + 98ba + ba98 + cdef
 *
 * Note: another presentation of the A transform can be found as the first
 * half of App. B.1 in [1] in terms of 4-byte operators P1, P2, P3 and P4.
 * The implementation below uses only P1 and P2 as they are sufficient.
 */
static inline void aria_a( uint32_t *a, uint32_t *b,
                           uint32_t *c, uint32_t *d )
{
    uint32_t ta, tb, tc;
    ta  =  *b;                      // 4567
    *b  =  *a;                      // 0123
    *a  =  ARIA_P2( ta );           // 6745
    tb  =  ARIA_P2( *d );           // efcd
    *d  =  ARIA_P1( *c );           // 98ba
    *c  =  ARIA_P1( tb );           // fedc
    ta  ^= *d;                      // 4567+98ba
    tc  =  ARIA_P2( *b );           // 2301
    ta  =  ARIA_P1( ta ) ^ tc ^ *c; // 2301+5476+89ab+fedc
    tb  ^= ARIA_P2( *d );           // ba98+efcd
    tc  ^= ARIA_P1( *a );           // 2301+7654
    *b  ^= ta ^ tb;                 // 0123+2301+5476+89ab+ba98+efcd+fedc OUT
    tb  =  ARIA_P2( tb ) ^ ta;      // 2301+5476+89ab+98ba+cdef+fedc
    *a  ^= ARIA_P1( tb );           // 3210+4567+6745+89ab+98ba+dcfe+efcd OUT
    ta  =  ARIA_P2( ta );           // 0123+7654+ab89+dcfe
    *d  ^= ARIA_P1( ta ) ^ tc;      // 1032+2301+6745+7654+98ba+ba98+cdef OUT
    tc  =  ARIA_P2( tc );           // 0123+5476
    *c  ^= ARIA_P1( tc ) ^ ta;      // 0123+1032+4567+7654+ab89+dcfe+fedc OUT
}

/*
 * ARIA Substitution Layer SL1 / SL2
 * (a, b, c, d) = state in/out
 * (sa, sb, sc, sd) = 256 8-bit S-Boxes (see below)
 *
 * By passing sb1, sb2, is1, is2 as S-Boxes you get SL1
 * By passing is1, is2, sb1, sb2 as S-Boxes you get SL2
 */
static inline void aria_sl( uint32_t *a, uint32_t *b,
                            uint32_t *c, uint32_t *d,
                            const uint8_t sa[256], const uint8_t sb[256],
                            const uint8_t sc[256], const uint8_t sd[256] )
{
    *a = ( (uint32_t) sa[ *a        & 0xFF]       ) ^
         (((uint32_t) sb[(*a >>  8) & 0xFF]) <<  8) ^
         (((uint32_t) sc[(*a >> 16) & 0xFF]) << 16) ^
         (((uint32_t) sd[ *a >> 24        ]) << 24);
    *b = ( (uint32_t) sa[ *b        & 0xFF]       ) ^
         (((uint32_t) sb[(*b >>  8) & 0xFF]) <<  8) ^
         (((uint32_t) sc[(*b >> 16) & 0xFF]) << 16) ^
         (((uint32_t) sd[ *b >> 24        ]) << 24);
    *c = ( (uint32_t) sa[ *c        & 0xFF]       ) ^
         (((uint32_t) sb[(*c >>  8) & 0xFF]) <<  8) ^
         (((uint32_t) sc[(*c >> 16) & 0xFF]) << 16) ^
         (((uint32_t) sd[ *c >> 24        ]) << 24);
    *d = ( (uint32_t) sa[ *d        & 0xFF]       ) ^
         (((uint32_t) sb[(*d >>  8) & 0xFF]) <<  8) ^
         (((uint32_t) sc[(*d >> 16) & 0xFF]) << 16) ^
         (((uint32_t) sd[ *d >> 24        ]) << 24);
}

/*
 * S-Boxes
 */
static const uint8_t aria_sb1[256] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF
};

static const uint8_t aria_sb2[256] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF
};

static const uint8_t aria_is1[256] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF
};

static const uint8_t aria_is2[256] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF
};

/*
 * Helper for key schedule: r = FO( p, k ) ^ x
 */
static void aria_fo_xor( uint32_t r[4], const uint32_t p[4],
                         const uint32_t k[4], const uint32_t x[4] )
{
    uint32_t a, b, c, d;

    a = p[0] ^ k[0];
    b = p[1] ^ k[1];
    c = p[2] ^ k[2];
    d = p[3] ^ k[3];

    aria_sl( &a, &b, &c, &d, aria_sb1, aria_sb2, aria_is1, aria_is2 );
    aria_a( &a, &b, &c, &d );

    r[0] = a ^ x[0];
    r[1] = b ^ x[1];
    r[2] = c ^ x[2];
    r[3] = d ^ x[3];
}

/*
 * Helper for key schedule: r = FE( p, k ) ^ x
 */
static void aria_fe_xor( uint32_t r[4], const uint32_t p[4],
                         const uint32_t k[4], const uint32_t x[4] )
{
    uint32_t a, b, c, d;

    a = p[0] ^ k[0];
    b = p[1] ^ k[1];
    c = p[2] ^ k[2];
    d = p[3] ^ k[3];

    aria_sl( &a, &b, &c, &d, aria_is1, aria_is2, aria_sb1, aria_sb2 );
    aria_a( &a, &b, &c, &d );

    r[0] = a ^ x[0];
    r[1] = b ^ x[1];
    r[2] = c ^ x[2];
    r[3] = d ^ x[3];
}

/*
 * Big endian 128-bit rotation: r = a ^ (b <<< n), used only in key setup.
 *
 * We chose to store bytes into 32-bit words in little-endian format (see
 * GET/PUT_UINT32_LE) so we need to reverse bytes here.
 */
static void aria_rot128( uint32_t r[4], const uint32_t a[4],
                         const uint32_t b[4], uint8_t n )
{
    uint8_t i, j;
    uint32_t t, u;

    const uint8_t n1 = n % 32;              // bit offset
    const uint8_t n2 = n1 ? 32 - n1 : 0;    // reverse bit offset

    j = ( n / 32 ) % 4;                     // initial word offset
    t = ARIA_P3( b[j] );                    // big endian
    for( i = 0; i < 4; i++ )
    {
        j = ( j + 1 ) % 4;                  // get next word, big endian
        u = ARIA_P3( b[j] );
        t <<= n1;                           // rotate
        t |= u >> n2;
        t = ARIA_P3( t );                   // back to little endian
        r[i] = a[i] ^ t;                    // store
        t = u;                              // move to next word
    }
}

/*
 * Set encryption key
 */
int mbedtls_aria_setkey_enc( mbedtls_aria_context *ctx,
                             const unsigned char *key, unsigned int keybits )
{
    /* round constant masks */
    const uint32_t rc[3][4] =
    {
        {   0xFF, 0xFF, 0xFF, 0xFF  },
        {   0xFF, 0xFF, 0xFF, 0xFF  },
        {   0xFF, 0xFF, 0xFF, 0xFF  }
    };

    int i;
    uint32_t w[4][4], *w2;

    if( keybits != 128 && keybits != 192 && keybits != 256 )
        return( MBEDTLS_ERR_ARIA_INVALID_KEY_LENGTH );

    /* Copy key to W0 (and potential remainder to W1) */
    GET_UINT32_LE( w[0][0], key,  0 );
    GET_UINT32_LE( w[0][1], key,  4 );
    GET_UINT32_LE( w[0][2], key,  8 );
    GET_UINT32_LE( w[0][3], key, 12 );

    memset( w[1], 0, 16 );
    if( keybits >= 192 )
    {
        GET_UINT32_LE( w[1][0], key, 16 );  // 192 bit key
        GET_UINT32_LE( w[1][1], key, 20 );
    }
    if( keybits == 256 )
    {
        GET_UINT32_LE( w[1][2], key, 24 );  // 256 bit key
        GET_UINT32_LE( w[1][3], key, 28 );
    }

    i = ( keybits - 128 ) >> 6;             // index: 0, 1, 2
    ctx->nr = 12 + 2 * i;                   // no. rounds: 12, 14, 16

    aria_fo_xor( w[1], w[0], rc[i], w[1] ); // W1 = FO(W0, CK1) ^ KR
    i = i < 2 ? i + 1 : 0;
    aria_fe_xor( w[2], w[1], rc[i], w[0] ); // W2 = FE(W1, CK2) ^ W0
    i = i < 2 ? i + 1 : 0;
    aria_fo_xor( w[3], w[2], rc[i], w[1] ); // W3 = FO(W2, CK3) ^ W1

    for( i = 0; i < 4; i++ )                // create round keys
    {
        w2 = w[(i + 1) & 3];
        aria_rot128( ctx->rk[i     ], w[i], w2, 128 - 19 );
        aria_rot128( ctx->rk[i +  4], w[i], w2, 128 - 31 );
        aria_rot128( ctx->rk[i +  8], w[i], w2,       61 );
        aria_rot128( ctx->rk[i + 12], w[i], w2,       31 );
    }
    aria_rot128( ctx->rk[16], w[0], w[1], 19 );

    /* w holds enough info to reconstruct the round keys */
    mbedtls_platform_zeroize( w, sizeof( w ) );

    return( 0 );
}

/*
 * Set decryption key
 */
int mbedtls_aria_setkey_dec( mbedtls_aria_context *ctx,
                             const unsigned char *key, unsigned int keybits )
{
    int i, j, k, ret;

    ret = mbedtls_aria_setkey_enc( ctx, key, keybits );
    if( ret != 0 )
        return( ret );

    /* flip the order of round keys */
    for( i = 0, j = ctx->nr; i < j; i++, j-- )
    {
        for( k = 0; k < 4; k++ )
        {
            uint32_t t = ctx->rk[i][k];
            ctx->rk[i][k] = ctx->rk[j][k];
            ctx->rk[j][k] = t;
        }
    }

    /* apply affine transform to middle keys */
    for( i = 1; i < ctx->nr; i++ )
    {
        aria_a( &ctx->rk[i][0], &ctx->rk[i][1],
                &ctx->rk[i][2], &ctx->rk[i][3] );
    }

    return( 0 );
}

/*
 * Encrypt a block
 */
int mbedtls_aria_crypt_ecb( mbedtls_aria_context *ctx,
                            const unsigned char input[MBEDTLS_ARIA_BLOCKSIZE],
                            unsigned char output[MBEDTLS_ARIA_BLOCKSIZE] )
{
    int i;

    uint32_t a, b, c, d;

    GET_UINT32_LE( a, input,  0 );
    GET_UINT32_LE( b, input,  4 );
    GET_UINT32_LE( c, input,  8 );
    GET_UINT32_LE( d, input, 12 );

    i = 0;
    while( 1 )
    {
        a ^= ctx->rk[i][0];
        b ^= ctx->rk[i][1];
        c ^= ctx->rk[i][2];
        d ^= ctx->rk[i][3];
        i++;

        aria_sl( &a, &b, &c, &d, aria_sb1, aria_sb2, aria_is1, aria_is2 );
        aria_a( &a, &b, &c, &d );

        a ^= ctx->rk[i][0];
        b ^= ctx->rk[i][1];
        c ^= ctx->rk[i][2];
        d ^= ctx->rk[i][3];
        i++;

        aria_sl( &a, &b, &c, &d, aria_is1, aria_is2, aria_sb1, aria_sb2 );
        if( i >= ctx->nr )
            break;
        aria_a( &a, &b, &c, &d );
    }

    /* final key mixing */
    a ^= ctx->rk[i][0];
    b ^= ctx->rk[i][1];
    c ^= ctx->rk[i][2];
    d ^= ctx->rk[i][3];

    PUT_UINT32_LE( a, output,  0 );
    PUT_UINT32_LE( b, output,  4 );
    PUT_UINT32_LE( c, output,  8 );
    PUT_UINT32_LE( d, output, 12 );

    return( 0 );
}

/* Initialize context */
void mbedtls_aria_init( mbedtls_aria_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_aria_context ) );
}

/* Clear context */
void mbedtls_aria_free( mbedtls_aria_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_aria_context ) );
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
/*
 * ARIA-CBC buffer encryption/decryption
 */
int mbedtls_aria_crypt_cbc( mbedtls_aria_context *ctx,
                            int mode,
                            size_t length,
                            unsigned char iv[MBEDTLS_ARIA_BLOCKSIZE],
                            const unsigned char *input,
                            unsigned char *output )
{
    int i;
    unsigned char temp[MBEDTLS_ARIA_BLOCKSIZE];

    if( length % MBEDTLS_ARIA_BLOCKSIZE )
        return( MBEDTLS_ERR_ARIA_INVALID_INPUT_LENGTH );

    if( mode == MBEDTLS_ARIA_DECRYPT )
    {
        while( length > 0 )
        {
            memcpy( temp, input, MBEDTLS_ARIA_BLOCKSIZE );
            mbedtls_aria_crypt_ecb( ctx, input, output );

            for( i = 0; i < MBEDTLS_ARIA_BLOCKSIZE; i++ )
                output[i] = (unsigned char)( output[i] ^ iv[i] );

            memcpy( iv, temp, MBEDTLS_ARIA_BLOCKSIZE );

            input  += MBEDTLS_ARIA_BLOCKSIZE;
            output += MBEDTLS_ARIA_BLOCKSIZE;
            length -= MBEDTLS_ARIA_BLOCKSIZE;
        }
    }
    else
    {
        while( length > 0 )
        {
            for( i = 0; i < MBEDTLS_ARIA_BLOCKSIZE; i++ )
                output[i] = (unsigned char)( input[i] ^ iv[i] );

            mbedtls_aria_crypt_ecb( ctx, output, output );
            memcpy( iv, output, MBEDTLS_ARIA_BLOCKSIZE );

            input  += MBEDTLS_ARIA_BLOCKSIZE;
            output += MBEDTLS_ARIA_BLOCKSIZE;
            length -= MBEDTLS_ARIA_BLOCKSIZE;
        }
    }

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
/*
 * ARIA-CFB128 buffer encryption/decryption
 */
int mbedtls_aria_crypt_cfb128( mbedtls_aria_context *ctx,
                               int mode,
                               size_t length,
                               size_t *iv_off,
                               unsigned char iv[MBEDTLS_ARIA_BLOCKSIZE],
                               const unsigned char *input,
                               unsigned char *output )
{
    unsigned char c;
    size_t n = *iv_off;

    if( mode == MBEDTLS_ARIA_DECRYPT )
    {
        while( length-- )
        {
            if( n == 0 )
                mbedtls_aria_crypt_ecb( ctx, iv, iv );

            c = *input++;
            *output++ = c ^ iv[n];
            iv[n] = c;

            n = ( n + 1 ) & 0xFF;
        }
    }
    else
    {
        while( length-- )
        {
            if( n == 0 )
                mbedtls_aria_crypt_ecb( ctx, iv, iv );

            iv[n] = *output++ = (unsigned char)( iv[n] ^ *input++ );

            n = ( n + 1 ) & 0xFF;
        }
    }

    *iv_off = n;

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
/*
 * ARIA-CTR buffer encryption/decryption
 */
int mbedtls_aria_crypt_ctr( mbedtls_aria_context *ctx,
                            size_t length,
                            size_t *nc_off,
                            unsigned char nonce_counter[MBEDTLS_ARIA_BLOCKSIZE],
                            unsigned char stream_block[MBEDTLS_ARIA_BLOCKSIZE],
                            const unsigned char *input,
                            unsigned char *output )
{
    int c, i;
    size_t n = *nc_off;

    while( length-- )
    {
        if( n == 0 ) {
            mbedtls_aria_crypt_ecb( ctx, nonce_counter,
                                stream_block );

            for( i = MBEDTLS_ARIA_BLOCKSIZE; i > 0; i-- )
                if( ++nonce_counter[i - 1] != 0 )
                    break;
        }
        c = *input++;
        *output++ = (unsigned char)( c ^ stream_block[n] );

        n = ( n + 1 ) & 0xFF;
    }

    *nc_off = n;

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_CTR */
#endif /* !MBEDTLS_ARIA_ALT */

#if defined(MBEDTLS_SELF_TEST)

/*
 * Basic ARIA ECB test vectors from RFC 5794
 */
static const uint8_t aria_test1_ecb_key[32] =           // test key
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,     // 128 bit
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,     // 192 bit
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF      // 256 bit
};

static const uint8_t aria_test1_ecb_pt[MBEDTLS_ARIA_BLOCKSIZE] =            // plaintext
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,     // same for all
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF      // key sizes
};

static const uint8_t aria_test1_ecb_ct[3][MBEDTLS_ARIA_BLOCKSIZE] =         // ciphertext
{
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // 128 bit
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // 192 bit
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // 256 bit
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }
};

/*
 * Mode tests from "Test Vectors for ARIA"  Version 1.0
 * http://210.104.33.10/ARIA/doc/ARIA-testvector-e.pdf
 */
#if (defined(MBEDTLS_CIPHER_MODE_CBC) || defined(MBEDTLS_CIPHER_MODE_CFB) || \
    defined(MBEDTLS_CIPHER_MODE_CTR))
static const uint8_t aria_test2_key[32] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,     // 128 bit
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,     // 192 bit
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF      // 256 bit
};

static const uint8_t aria_test2_pt[48] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,     // same for all
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};
#endif

#if (defined(MBEDTLS_CIPHER_MODE_CBC) || defined(MBEDTLS_CIPHER_MODE_CFB))
static const uint8_t aria_test2_iv[MBEDTLS_ARIA_BLOCKSIZE] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,     // same for CBC, CFB
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF      // CTR has zero IV
};
#endif

#if defined(MBEDTLS_CIPHER_MODE_CBC)
static const uint8_t aria_test2_cbc_ct[3][48] =         // CBC ciphertext
{
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // 128-bit key
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // 192-bit key
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // 256-bit key
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }
};
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
static const uint8_t aria_test2_cfb_ct[3][48] =         // CFB ciphertext
{
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // 128-bit key
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // 192-bit key
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // 256-bit key
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }
};
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
static const uint8_t aria_test2_ctr_ct[3][48] =         // CTR ciphertext
{
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // 128-bit key
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // 192-bit key
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // 256-bit key
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }
};
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#define ARIA_SELF_TEST_IF_FAIL              \
        {                                   \
            if( verbose )                   \
                mbedtls_printf( "failed\n" );       \
            return( 1 );                    \
        } else {                            \
            if( verbose )                   \
                mbedtls_printf( "passed\n" );       \
        }

/*
 * Checkup routine
 */
int mbedtls_aria_self_test( int verbose )
{
    int i;
    uint8_t blk[MBEDTLS_ARIA_BLOCKSIZE];
    mbedtls_aria_context ctx;

#if (defined(MBEDTLS_CIPHER_MODE_CFB) || defined(MBEDTLS_CIPHER_MODE_CTR))
    size_t j;
#endif

#if (defined(MBEDTLS_CIPHER_MODE_CBC) || \
     defined(MBEDTLS_CIPHER_MODE_CFB) || \
     defined(MBEDTLS_CIPHER_MODE_CTR))
    uint8_t buf[48], iv[MBEDTLS_ARIA_BLOCKSIZE];
#endif

    /*
     * Test set 1
     */
    for( i = 0; i < 3; i++ )
    {
        /* test ECB encryption */
        if( verbose )
            mbedtls_printf( "  ARIA-ECB-%d (enc): ", 128 + 64 * i );
        mbedtls_aria_setkey_enc( &ctx, aria_test1_ecb_key, 128 + 64 * i );
        mbedtls_aria_crypt_ecb( &ctx, aria_test1_ecb_pt, blk );
        if( memcmp( blk, aria_test1_ecb_ct[i], MBEDTLS_ARIA_BLOCKSIZE ) != 0 )
            ARIA_SELF_TEST_IF_FAIL;

        /* test ECB decryption */
        if( verbose )
            mbedtls_printf( "  ARIA-ECB-%d (dec): ", 128 + 64 * i );
        mbedtls_aria_setkey_dec( &ctx, aria_test1_ecb_key, 128 + 64 * i );
        mbedtls_aria_crypt_ecb( &ctx, aria_test1_ecb_ct[i], blk );
        if( memcmp( blk, aria_test1_ecb_pt, MBEDTLS_ARIA_BLOCKSIZE ) != 0 )
            ARIA_SELF_TEST_IF_FAIL;
    }
    if( verbose )
        mbedtls_printf( "\n" );

    /*
     * Test set 2
     */
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    for( i = 0; i < 3; i++ )
    {
        /* Test CBC encryption */
        if( verbose )
            mbedtls_printf( "  ARIA-CBC-%d (enc): ", 128 + 64 * i );
        mbedtls_aria_setkey_enc( &ctx, aria_test2_key, 128 + 64 * i );
        memcpy( iv, aria_test2_iv, MBEDTLS_ARIA_BLOCKSIZE );
        memset( buf, 0xFF, sizeof( buf ) );
        mbedtls_aria_crypt_cbc( &ctx, MBEDTLS_ARIA_ENCRYPT, 48, iv,
            aria_test2_pt, buf );
        if( memcmp( buf, aria_test2_cbc_ct[i], 48 ) != 0 )
            ARIA_SELF_TEST_IF_FAIL;

        /* Test CBC decryption */
        if( verbose )
            mbedtls_printf( "  ARIA-CBC-%d (dec): ", 128 + 64 * i );
        mbedtls_aria_setkey_dec( &ctx, aria_test2_key, 128 + 64 * i );
        memcpy( iv, aria_test2_iv, MBEDTLS_ARIA_BLOCKSIZE );
        memset( buf, 0xFF, sizeof( buf ) );
        mbedtls_aria_crypt_cbc( &ctx, MBEDTLS_ARIA_DECRYPT, 48, iv,
            aria_test2_cbc_ct[i], buf );
        if( memcmp( buf, aria_test2_pt, 48 ) != 0 )
            ARIA_SELF_TEST_IF_FAIL;
    }
    if( verbose )
        mbedtls_printf( "\n" );

#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
    for( i = 0; i < 3; i++ )
    {
        /* Test CFB encryption */
        if( verbose )
            mbedtls_printf( "  ARIA-CFB-%d (enc): ", 128 + 64 * i );
        mbedtls_aria_setkey_enc( &ctx, aria_test2_key, 128 + 64 * i );
        memcpy( iv, aria_test2_iv, MBEDTLS_ARIA_BLOCKSIZE );
        memset( buf, 0xFF, sizeof( buf ) );
        j = 0;
        mbedtls_aria_crypt_cfb128( &ctx, MBEDTLS_ARIA_ENCRYPT, 48, &j, iv,
            aria_test2_pt, buf );
        if( memcmp( buf, aria_test2_cfb_ct[i], 48 ) != 0 )
            ARIA_SELF_TEST_IF_FAIL;

        /* Test CFB decryption */
        if( verbose )
            mbedtls_printf( "  ARIA-CFB-%d (dec): ", 128 + 64 * i );
        mbedtls_aria_setkey_enc( &ctx, aria_test2_key, 128 + 64 * i );
        memcpy( iv, aria_test2_iv, MBEDTLS_ARIA_BLOCKSIZE );
        memset( buf, 0xFF, sizeof( buf ) );
        j = 0;
        mbedtls_aria_crypt_cfb128( &ctx, MBEDTLS_ARIA_DECRYPT, 48, &j,
            iv, aria_test2_cfb_ct[i], buf );
        if( memcmp( buf, aria_test2_pt, 48 ) != 0 )
            ARIA_SELF_TEST_IF_FAIL;
    }
    if( verbose )
        mbedtls_printf( "\n" );
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
    for( i = 0; i < 3; i++ )
    {
        /* Test CTR encryption */
        if( verbose )
            mbedtls_printf( "  ARIA-CTR-%d (enc): ", 128 + 64 * i );
        mbedtls_aria_setkey_enc( &ctx, aria_test2_key, 128 + 64 * i );
        memset( iv, 0, MBEDTLS_ARIA_BLOCKSIZE );                    // IV = 0
        memset( buf, 0xFF, sizeof( buf ) );
        j = 0;
        mbedtls_aria_crypt_ctr( &ctx, 48, &j, iv, blk,
            aria_test2_pt, buf );
        if( memcmp( buf, aria_test2_ctr_ct[i], 48 ) != 0 )
            ARIA_SELF_TEST_IF_FAIL;

        /* Test CTR decryption */
        if( verbose )
            mbedtls_printf( "  ARIA-CTR-%d (dec): ", 128 + 64 * i );
        mbedtls_aria_setkey_enc( &ctx, aria_test2_key, 128 + 64 * i );
        memset( iv, 0, MBEDTLS_ARIA_BLOCKSIZE );                    // IV = 0
        memset( buf, 0xFF, sizeof( buf ) );
        j = 0;
        mbedtls_aria_crypt_ctr( &ctx, 48, &j, iv, blk,
            aria_test2_ctr_ct[i], buf );
        if( memcmp( buf, aria_test2_pt, 48 ) != 0 )
            ARIA_SELF_TEST_IF_FAIL;
    }
    if( verbose )
        mbedtls_printf( "\n" );
#endif /* MBEDTLS_CIPHER_MODE_CTR */

    return( 0 );
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_ARIA_C */
