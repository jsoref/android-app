/*
 * Copyright 2006-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This is experimental x86[_64] derivative. It assumes little-endian
 * byte order and expects CPU to sustain unaligned memory references.
 * It is used as playground for cache-time attack mitigations and
 * serves as reference C implementation for x86[_64] as well as some
 * other assembly modules.
 */

/**
 * rijndael-alg-fst.c
 *
 * @version 3.0 (December 2000)
 *
 * Optimised ANSI C code for the Rijndael cipher (now AES)
 *
 * @author Vincent Rijmen
 * @author Antoon Bosselaers
 * @author Paulo Barreto
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <assert.h>

#include <stdlib.h>
#include <openssl/aes.h>
#include "aes_locl.h"

/*
 * These two parameters control which table, 256-byte or 2KB, is
 * referenced in outer and respectively inner rounds.
 */
#define AES_COMPACT_IN_OUTER_ROUNDS
#ifdef  AES_COMPACT_IN_OUTER_ROUNDS
/* AES_COMPACT_IN_OUTER_ROUNDS costs ~30% in performance, while
 * adding AES_COMPACT_IN_INNER_ROUNDS reduces benchmark *further*
 * by factor of ~2. */
# undef  AES_COMPACT_IN_INNER_ROUNDS
#endif

#if 1
static void prefetch256(const void *table)
{
    volatile unsigned long *t=(void *)table,ret;
    unsigned long sum;
    int i;

    /* 32 is common least cache-line size */
    for (sum=0,i=0;i<256/sizeof(t[0]);i+=32/sizeof(t[0]))   sum ^= t[i];

    ret = sum;
}
#else
# define prefetch256(t)
#endif

#undef GETU32
#define GETU32(p) (*((u32*)(p)))

#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
typedef unsigned __int64 u64;
#define U64(C)  C##UI64
#elif defined(__arch64__)
typedef unsigned long u64;
#define U64(C)  C##UL
#else
typedef unsigned long long u64;
#define U64(C)  C##ULL
#endif

#undef ROTATE
#if defined(_MSC_VER)
# define ROTATE(a,n)    _lrotl(a,n)
#elif defined(__ICC)
# define ROTATE(a,n)    _rotl(a,n)
#elif defined(__GNUC__) && __GNUC__>=2
# if defined(__i386) || defined(__i386__) || defined(__x86_64) || defined(__x86_64__)
#   define ROTATE(a,n)  ({ register unsigned int ret;   \
                asm (           \
                "roll %1,%0"        \
                : "=r"(ret)     \
                : "I"(n), "0"(a)    \
                : "cc");        \
               ret;             \
            })
# endif
#endif
/*-
Te [x] = S [x].[02, 01, 01, 03, 02, 01, 01, 03];
Te0[x] = S [x].[02, 01, 01, 03];
Te1[x] = S [x].[03, 02, 01, 01];
Te2[x] = S [x].[01, 03, 02, 01];
Te3[x] = S [x].[01, 01, 03, 02];
*/
#define Te0 (u32)((u64*)((u8*)Te+0))
#define Te1 (u32)((u64*)((u8*)Te+3))
#define Te2 (u32)((u64*)((u8*)Te+2))
#define Te3 (u32)((u64*)((u8*)Te+1))
/*-
Td [x] = Si[x].[0e, 09, 0d, 0b, 0e, 09, 0d, 0b];
Td0[x] = Si[x].[0e, 09, 0d, 0b];
Td1[x] = Si[x].[0b, 0e, 09, 0d];
Td2[x] = Si[x].[0d, 0b, 0e, 09];
Td3[x] = Si[x].[09, 0d, 0b, 0e];
Td4[x] = Si[x].[01];
*/
#define Td0 (u32)((u64*)((u8*)Td+0))
#define Td1 (u32)((u64*)((u8*)Td+3))
#define Td2 (u32)((u64*)((u8*)Td+2))
#define Td3 (u32)((u64*)((u8*)Td+1))

static const u64 Te[256] = {
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF)
};

static const u8 Te4[256] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU
};

static const u64 Td[256] = {
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF),
    U64(0xFF), U64(0xFF)
};
static const u8 Td4[256] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU
};

static const u32 rcon[] = {
    0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, /* for 128-bit blocks, Rijndael never uses more than 10 rcon values */
};

/**
 * Expand the cipher key into the encryption key schedule.
 */
int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key)
{

    u32 *rk;
    int i = 0;
    u32 temp;

    if (!userKey || !key)
        return -1;
    if (bits != 128 && bits != 192 && bits != 256)
        return -2;

    rk = key->rd_key;

    if (bits==128)
        key->rounds = 10;
    else if (bits==192)
        key->rounds = 12;
    else
        key->rounds = 14;

    rk[0] = GETU32(userKey     );
    rk[1] = GETU32(userKey +  4);
    rk[2] = GETU32(userKey +  8);
    rk[3] = GETU32(userKey + 12);
    if (bits == 128) {
        while (1) {
            temp  = rk[3];
            rk[4] = rk[0] ^
                ((u32)Te4[(temp >>  8) & 0xFF]      ) ^
                ((u32)Te4[(temp >> 16) & 0xFF] <<  8) ^
                ((u32)Te4[(temp >> 24)       ] << 16) ^
                ((u32)Te4[(temp      ) & 0xFF] << 24) ^
                rcon[i];
            rk[5] = rk[1] ^ rk[4];
            rk[6] = rk[2] ^ rk[5];
            rk[7] = rk[3] ^ rk[6];
            if (++i == 10) {
                return 0;
            }
            rk += 4;
        }
    }
    rk[4] = GETU32(userKey + 16);
    rk[5] = GETU32(userKey + 20);
    if (bits == 192) {
        while (1) {
            temp = rk[ 5];
            rk[ 6] = rk[ 0] ^
                ((u32)Te4[(temp >>  8) & 0xFF]      ) ^
                ((u32)Te4[(temp >> 16) & 0xFF] <<  8) ^
                ((u32)Te4[(temp >> 24)       ] << 16) ^
                ((u32)Te4[(temp      ) & 0xFF] << 24) ^
                rcon[i];
            rk[ 7] = rk[ 1] ^ rk[ 6];
            rk[ 8] = rk[ 2] ^ rk[ 7];
            rk[ 9] = rk[ 3] ^ rk[ 8];
            if (++i == 8) {
                return 0;
            }
            rk[10] = rk[ 4] ^ rk[ 9];
            rk[11] = rk[ 5] ^ rk[10];
            rk += 6;
        }
    }
    rk[6] = GETU32(userKey + 24);
    rk[7] = GETU32(userKey + 28);
    if (bits == 256) {
        while (1) {
            temp = rk[ 7];
            rk[ 8] = rk[ 0] ^
                ((u32)Te4[(temp >>  8) & 0xFF]      ) ^
                ((u32)Te4[(temp >> 16) & 0xFF] <<  8) ^
                ((u32)Te4[(temp >> 24)       ] << 16) ^
                ((u32)Te4[(temp      ) & 0xFF] << 24) ^
                rcon[i];
            rk[ 9] = rk[ 1] ^ rk[ 8];
            rk[10] = rk[ 2] ^ rk[ 9];
            rk[11] = rk[ 3] ^ rk[10];
            if (++i == 7) {
                return 0;
            }
            temp = rk[11];
            rk[12] = rk[ 4] ^
                ((u32)Te4[(temp      ) & 0xFF]      ) ^
                ((u32)Te4[(temp >>  8) & 0xFF] <<  8) ^
                ((u32)Te4[(temp >> 16) & 0xFF] << 16) ^
                ((u32)Te4[(temp >> 24)       ] << 24);
            rk[13] = rk[ 5] ^ rk[12];
            rk[14] = rk[ 6] ^ rk[13];
            rk[15] = rk[ 7] ^ rk[14];

            rk += 8;
            }
    }
    return 0;
}

/**
 * Expand the cipher key into the decryption key schedule.
 */
int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key)
{

    u32 *rk;
    int i, j, status;
    u32 temp;

    /* first, start with an encryption schedule */
    status = AES_set_encrypt_key(userKey, bits, key);
    if (status < 0)
        return status;

    rk = key->rd_key;

    /* invert the order of the round keys: */
    for (i = 0, j = 4*(key->rounds); i < j; i += 4, j -= 4) {
        temp = rk[i    ]; rk[i    ] = rk[j    ]; rk[j    ] = temp;
        temp = rk[i + 1]; rk[i + 1] = rk[j + 1]; rk[j + 1] = temp;
        temp = rk[i + 2]; rk[i + 2] = rk[j + 2]; rk[j + 2] = temp;
        temp = rk[i + 3]; rk[i + 3] = rk[j + 3]; rk[j + 3] = temp;
    }
    /* apply the inverse MixColumn transform to all round keys but the first and the last: */
    for (i = 1; i < (key->rounds); i++) {
        rk += 4;
#if 1
        for (j = 0; j < 4; j++) {
            u32 tp1, tp2, tp4, tp8, tp9, tpb, tpd, tpe, m;

            tp1 = rk[j];
            m = tp1 & 0xFF;
            tp2 = ((tp1 & 0xFF) << 1) ^
                ((m - (m >> 7)) & 0xFF);
            m = tp2 & 0xFF;
            tp4 = ((tp2 & 0xFF) << 1) ^
                ((m - (m >> 7)) & 0xFF);
            m = tp4 & 0xFF;
            tp8 = ((tp4 & 0xFF) << 1) ^
                ((m - (m >> 7)) & 0xFF);
            tp9 = tp8 ^ tp1;
            tpb = tp9 ^ tp2;
            tpd = tp9 ^ tp4;
            tpe = tp8 ^ tp4 ^ tp2;
#if defined(ROTATE)
            rk[j] = tpe ^ ROTATE(tpd,16) ^
                ROTATE(tp9,8) ^ ROTATE(tpb,24);
#else
            rk[j] = tpe ^ (tpd >> 16) ^ (tpd << 16) ^
                (tp9 >> 24) ^ (tp9 << 8) ^
                (tpb >> 8) ^ (tpb << 24);
#endif
        }
#else
        rk[0] =
            Td0[Te2[(rk[0]      ) & 0xFF] & 0xFF] ^
            Td1[Te2[(rk[0] >>  8) & 0xFF] & 0xFF] ^
            Td2[Te2[(rk[0] >> 16) & 0xFF] & 0xFF] ^
            Td3[Te2[(rk[0] >> 24)       ] & 0xFF];
        rk[1] =
            Td0[Te2[(rk[1]      ) & 0xFF] & 0xFF] ^
            Td1[Te2[(rk[1] >>  8) & 0xFF] & 0xFF] ^
            Td2[Te2[(rk[1] >> 16) & 0xFF] & 0xFF] ^
            Td3[Te2[(rk[1] >> 24)       ] & 0xFF];
        rk[2] =
            Td0[Te2[(rk[2]      ) & 0xFF] & 0xFF] ^
            Td1[Te2[(rk[2] >>  8) & 0xFF] & 0xFF] ^
            Td2[Te2[(rk[2] >> 16) & 0xFF] & 0xFF] ^
            Td3[Te2[(rk[2] >> 24)       ] & 0xFF];
        rk[3] =
            Td0[Te2[(rk[3]      ) & 0xFF] & 0xFF] ^
            Td1[Te2[(rk[3] >>  8) & 0xFF] & 0xFF] ^
            Td2[Te2[(rk[3] >> 16) & 0xFF] & 0xFF] ^
            Td3[Te2[(rk[3] >> 24)       ] & 0xFF];
#endif
    }
    return 0;
}

/*
 * Encrypt a single block
 * in and out can overlap
 */
void AES_encrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key)
{

    const u32 *rk;
    u32 s0, s1, s2, s3, t[4];
    int r;

    assert(in && out && key);
    rk = key->rd_key;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    s0 = GETU32(in     ) ^ rk[0];
    s1 = GETU32(in +  4) ^ rk[1];
    s2 = GETU32(in +  8) ^ rk[2];
    s3 = GETU32(in + 12) ^ rk[3];

#if defined(AES_COMPACT_IN_OUTER_ROUNDS)
    prefetch256(Te4);

    t[0] = (u32)Te4[(s0      ) & 0xFF]       ^
           (u32)Te4[(s1 >>  8) & 0xFF] <<  8 ^
           (u32)Te4[(s2 >> 16) & 0xFF] << 16 ^
           (u32)Te4[(s3 >> 24)       ] << 24;
    t[1] = (u32)Te4[(s1      ) & 0xFF]       ^
           (u32)Te4[(s2 >>  8) & 0xFF] <<  8 ^
           (u32)Te4[(s3 >> 16) & 0xFF] << 16 ^
           (u32)Te4[(s0 >> 24)       ] << 24;
    t[2] = (u32)Te4[(s2      ) & 0xFF]       ^
           (u32)Te4[(s3 >>  8) & 0xFF] <<  8 ^
           (u32)Te4[(s0 >> 16) & 0xFF] << 16 ^
           (u32)Te4[(s1 >> 24)       ] << 24;
    t[3] = (u32)Te4[(s3      ) & 0xFF]       ^
           (u32)Te4[(s0 >>  8) & 0xFF] <<  8 ^
           (u32)Te4[(s1 >> 16) & 0xFF] << 16 ^
           (u32)Te4[(s2 >> 24)       ] << 24;

    /* now do the linear transform using words */
    {   int i;
        u32 r0, r1, r2;

        for (i = 0; i < 4; i++) {
            r0 = t[i];
            r1 = r0 & 0xFF;
            r2 = ((r0 & 0xFF) << 1) ^
                ((r1 - (r1 >> 7)) & 0xFF);
#if defined(ROTATE)
            t[i] = r2 ^ ROTATE(r2,24) ^ ROTATE(r0,24) ^
                ROTATE(r0,16) ^ ROTATE(r0,8);
#else
            t[i] = r2 ^ ((r2 ^ r0) << 24) ^ ((r2 ^ r0) >> 8) ^
                (r0 << 16) ^ (r0 >> 16) ^
                (r0 << 8) ^ (r0 >> 24);
#endif
            t[i] ^= rk[4+i];
        }
    }
#else
    t[0] =  Te0[(s0      ) & 0xFF] ^
        Te1[(s1 >>  8) & 0xFF] ^
        Te2[(s2 >> 16) & 0xFF] ^
        Te3[(s3 >> 24)       ] ^
        rk[4];
    t[1] =  Te0[(s1      ) & 0xFF] ^
        Te1[(s2 >>  8) & 0xFF] ^
        Te2[(s3 >> 16) & 0xFF] ^
        Te3[(s0 >> 24)       ] ^
        rk[5];
    t[2] =  Te0[(s2      ) & 0xFF] ^
        Te1[(s3 >>  8) & 0xFF] ^
        Te2[(s0 >> 16) & 0xFF] ^
        Te3[(s1 >> 24)       ] ^
        rk[6];
    t[3] =  Te0[(s3      ) & 0xFF] ^
        Te1[(s0 >>  8) & 0xFF] ^
        Te2[(s1 >> 16) & 0xFF] ^
        Te3[(s2 >> 24)       ] ^
        rk[7];
#endif
    s0 = t[0]; s1 = t[1]; s2 = t[2]; s3 = t[3];

    /*
     * Nr - 2 full rounds:
     */
    for (rk+=8,r=key->rounds-2; r>0; rk+=4,r--) {
#if defined(AES_COMPACT_IN_INNER_ROUNDS)
        t[0] = (u32)Te4[(s0      ) & 0xFF]       ^
               (u32)Te4[(s1 >>  8) & 0xFF] <<  8 ^
               (u32)Te4[(s2 >> 16) & 0xFF] << 16 ^
               (u32)Te4[(s3 >> 24)       ] << 24;
        t[1] = (u32)Te4[(s1      ) & 0xFF]       ^
               (u32)Te4[(s2 >>  8) & 0xFF] <<  8 ^
               (u32)Te4[(s3 >> 16) & 0xFF] << 16 ^
               (u32)Te4[(s0 >> 24)       ] << 24;
        t[2] = (u32)Te4[(s2      ) & 0xFF]       ^
               (u32)Te4[(s3 >>  8) & 0xFF] <<  8 ^
               (u32)Te4[(s0 >> 16) & 0xFF] << 16 ^
               (u32)Te4[(s1 >> 24)       ] << 24;
        t[3] = (u32)Te4[(s3      ) & 0xFF]       ^
               (u32)Te4[(s0 >>  8) & 0xFF] <<  8 ^
               (u32)Te4[(s1 >> 16) & 0xFF] << 16 ^
               (u32)Te4[(s2 >> 24)       ] << 24;

        /* now do the linear transform using words */
        {
            int i;
            u32 r0, r1, r2;

            for (i = 0; i < 4; i++) {
                r0 = t[i];
                r1 = r0 & 0xFF;
                r2 = ((r0 & 0xFF) << 1) ^
                    ((r1 - (r1 >> 7)) & 0xFF);
#if defined(ROTATE)
                t[i] = r2 ^ ROTATE(r2,24) ^ ROTATE(r0,24) ^
                    ROTATE(r0,16) ^ ROTATE(r0,8);
#else
                t[i] = r2 ^ ((r2 ^ r0) << 24) ^ ((r2 ^ r0) >> 8) ^
                    (r0 << 16) ^ (r0 >> 16) ^
                    (r0 << 8) ^ (r0 >> 24);
#endif
                t[i] ^= rk[i];
            }
        }
#else
        t[0] =  Te0[(s0      ) & 0xFF] ^
            Te1[(s1 >>  8) & 0xFF] ^
            Te2[(s2 >> 16) & 0xFF] ^
            Te3[(s3 >> 24)       ] ^
            rk[0];
        t[1] =  Te0[(s1      ) & 0xFF] ^
            Te1[(s2 >>  8) & 0xFF] ^
            Te2[(s3 >> 16) & 0xFF] ^
            Te3[(s0 >> 24)       ] ^
            rk[1];
        t[2] =  Te0[(s2      ) & 0xFF] ^
            Te1[(s3 >>  8) & 0xFF] ^
            Te2[(s0 >> 16) & 0xFF] ^
            Te3[(s1 >> 24)       ] ^
            rk[2];
        t[3] =  Te0[(s3      ) & 0xFF] ^
            Te1[(s0 >>  8) & 0xFF] ^
            Te2[(s1 >> 16) & 0xFF] ^
            Te3[(s2 >> 24)       ] ^
            rk[3];
#endif
        s0 = t[0]; s1 = t[1]; s2 = t[2]; s3 = t[3];
    }
    /*
     * apply last round and
     * map cipher state to byte array block:
     */
#if defined(AES_COMPACT_IN_OUTER_ROUNDS)
    prefetch256(Te4);

    *(u32*)(out+0) =
           (u32)Te4[(s0      ) & 0xFF]       ^
           (u32)Te4[(s1 >>  8) & 0xFF] <<  8 ^
           (u32)Te4[(s2 >> 16) & 0xFF] << 16 ^
           (u32)Te4[(s3 >> 24)       ] << 24 ^
        rk[0];
    *(u32*)(out+4) =
           (u32)Te4[(s1      ) & 0xFF]       ^
           (u32)Te4[(s2 >>  8) & 0xFF] <<  8 ^
           (u32)Te4[(s3 >> 16) & 0xFF] << 16 ^
           (u32)Te4[(s0 >> 24)       ] << 24 ^
        rk[1];
    *(u32*)(out+8) =
           (u32)Te4[(s2      ) & 0xFF]       ^
           (u32)Te4[(s3 >>  8) & 0xFF] <<  8 ^
           (u32)Te4[(s0 >> 16) & 0xFF] << 16 ^
           (u32)Te4[(s1 >> 24)       ] << 24 ^
        rk[2];
    *(u32*)(out+12) =
           (u32)Te4[(s3      ) & 0xFF]       ^
           (u32)Te4[(s0 >>  8) & 0xFF] <<  8 ^
           (u32)Te4[(s1 >> 16) & 0xFF] << 16 ^
           (u32)Te4[(s2 >> 24)       ] << 24 ^
        rk[3];
#else
    *(u32*)(out+0) =
        (Te2[(s0      ) & 0xFF] & 0xFFU) ^
        (Te3[(s1 >>  8) & 0xFF] & 0xFFU) ^
        (Te0[(s2 >> 16) & 0xFF] & 0xFFU) ^
        (Te1[(s3 >> 24)       ] & 0xFFU) ^
        rk[0];
    *(u32*)(out+4) =
        (Te2[(s1      ) & 0xFF] & 0xFFU) ^
        (Te3[(s2 >>  8) & 0xFF] & 0xFFU) ^
        (Te0[(s3 >> 16) & 0xFF] & 0xFFU) ^
        (Te1[(s0 >> 24)       ] & 0xFFU) ^
        rk[1];
    *(u32*)(out+8) =
        (Te2[(s2      ) & 0xFF] & 0xFFU) ^
        (Te3[(s3 >>  8) & 0xFF] & 0xFFU) ^
        (Te0[(s0 >> 16) & 0xFF] & 0xFFU) ^
        (Te1[(s1 >> 24)       ] & 0xFFU) ^
        rk[2];
    *(u32*)(out+12) =
        (Te2[(s3      ) & 0xFF] & 0xFFU) ^
        (Te3[(s0 >>  8) & 0xFF] & 0xFFU) ^
        (Te0[(s1 >> 16) & 0xFF] & 0xFFU) ^
        (Te1[(s2 >> 24)       ] & 0xFFU) ^
        rk[3];
#endif
}

/*
 * Decrypt a single block
 * in and out can overlap
 */
void AES_decrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key)
{

    const u32 *rk;
    u32 s0, s1, s2, s3, t[4];
    int r;

    assert(in && out && key);
    rk = key->rd_key;

    /*
     * map byte array block to cipher state
     * and add initial round key:
     */
    s0 = GETU32(in     ) ^ rk[0];
    s1 = GETU32(in +  4) ^ rk[1];
    s2 = GETU32(in +  8) ^ rk[2];
    s3 = GETU32(in + 12) ^ rk[3];

#if defined(AES_COMPACT_IN_OUTER_ROUNDS)
    prefetch256(Td4);

    t[0] = (u32)Td4[(s0      ) & 0xFF]       ^
           (u32)Td4[(s3 >>  8) & 0xFF] <<  8 ^
           (u32)Td4[(s2 >> 16) & 0xFF] << 16 ^
           (u32)Td4[(s1 >> 24)       ] << 24;
    t[1] = (u32)Td4[(s1      ) & 0xFF]       ^
           (u32)Td4[(s0 >>  8) & 0xFF] <<  8 ^
           (u32)Td4[(s3 >> 16) & 0xFF] << 16 ^
           (u32)Td4[(s2 >> 24)       ] << 24;
    t[2] = (u32)Td4[(s2      ) & 0xFF]       ^
           (u32)Td4[(s1 >>  8) & 0xFF] <<  8 ^
           (u32)Td4[(s0 >> 16) & 0xFF] << 16 ^
           (u32)Td4[(s3 >> 24)       ] << 24;
    t[3] = (u32)Td4[(s3      ) & 0xFF]       ^
           (u32)Td4[(s2 >>  8) & 0xFF] <<  8 ^
           (u32)Td4[(s1 >> 16) & 0xFF] << 16 ^
           (u32)Td4[(s0 >> 24)       ] << 24;

    /* now do the linear transform using words */
    {
        int i;
        u32 tp1, tp2, tp4, tp8, tp9, tpb, tpd, tpe, m;

        for (i = 0; i < 4; i++) {
            tp1 = t[i];
            m = tp1 & 0xFF;
            tp2 = ((tp1 & 0xFF) << 1) ^
                ((m - (m >> 7)) & 0xFF);
            m = tp2 & 0xFF;
            tp4 = ((tp2 & 0xFF) << 1) ^
                ((m - (m >> 7)) & 0xFF);
            m = tp4 & 0xFF;
            tp8 = ((tp4 & 0xFF) << 1) ^
                ((m - (m >> 7)) & 0xFF);
            tp9 = tp8 ^ tp1;
            tpb = tp9 ^ tp2;
            tpd = tp9 ^ tp4;
            tpe = tp8 ^ tp4 ^ tp2;
#if defined(ROTATE)
            t[i] = tpe ^ ROTATE(tpd,16) ^
                ROTATE(tp9,8) ^ ROTATE(tpb,24);
#else
            t[i] = tpe ^ (tpd >> 16) ^ (tpd << 16) ^
                (tp9 >> 24) ^ (tp9 << 8) ^
                (tpb >> 8) ^ (tpb << 24);
#endif
            t[i] ^= rk[4+i];
        }
    }
#else
    t[0] =  Td0[(s0      ) & 0xFF] ^
        Td1[(s3 >>  8) & 0xFF] ^
        Td2[(s2 >> 16) & 0xFF] ^
        Td3[(s1 >> 24)       ] ^
        rk[4];
    t[1] =  Td0[(s1      ) & 0xFF] ^
        Td1[(s0 >>  8) & 0xFF] ^
        Td2[(s3 >> 16) & 0xFF] ^
        Td3[(s2 >> 24)       ] ^
        rk[5];
    t[2] =  Td0[(s2      ) & 0xFF] ^
        Td1[(s1 >>  8) & 0xFF] ^
        Td2[(s0 >> 16) & 0xFF] ^
        Td3[(s3 >> 24)       ] ^
        rk[6];
    t[3] =  Td0[(s3      ) & 0xFF] ^
        Td1[(s2 >>  8) & 0xFF] ^
        Td2[(s1 >> 16) & 0xFF] ^
        Td3[(s0 >> 24)       ] ^
        rk[7];
#endif
    s0 = t[0]; s1 = t[1]; s2 = t[2]; s3 = t[3];

    /*
     * Nr - 2 full rounds:
     */
    for (rk+=8,r=key->rounds-2; r>0; rk+=4,r--) {
#if defined(AES_COMPACT_IN_INNER_ROUNDS)
        t[0] = (u32)Td4[(s0      ) & 0xFF]       ^
               (u32)Td4[(s3 >>  8) & 0xFF] <<  8 ^
               (u32)Td4[(s2 >> 16) & 0xFF] << 16 ^
               (u32)Td4[(s1 >> 24)       ] << 24;
        t[1] = (u32)Td4[(s1      ) & 0xFF]       ^
               (u32)Td4[(s0 >>  8) & 0xFF] <<  8 ^
               (u32)Td4[(s3 >> 16) & 0xFF] << 16 ^
               (u32)Td4[(s2 >> 24)       ] << 24;
        t[2] = (u32)Td4[(s2      ) & 0xFF]       ^
               (u32)Td4[(s1 >>  8) & 0xFF] <<  8 ^
               (u32)Td4[(s0 >> 16) & 0xFF] << 16 ^
               (u32)Td4[(s3 >> 24)       ] << 24;
        t[3] = (u32)Td4[(s3      ) & 0xFF]       ^
               (u32)Td4[(s2 >>  8) & 0xFF] <<  8 ^
               (u32)Td4[(s1 >> 16) & 0xFF] << 16 ^
               (u32)Td4[(s0 >> 24)       ] << 24;

    /* now do the linear transform using words */
    {
        int i;
        u32 tp1, tp2, tp4, tp8, tp9, tpb, tpd, tpe, m;

        for (i = 0; i < 4; i++) {
            tp1 = t[i];
            m = tp1 & 0xFF;
            tp2 = ((tp1 & 0xFF) << 1) ^
                ((m - (m >> 7)) & 0xFF);
            m = tp2 & 0xFF;
            tp4 = ((tp2 & 0xFF) << 1) ^
                ((m - (m >> 7)) & 0xFF);
            m = tp4 & 0xFF;
            tp8 = ((tp4 & 0xFF) << 1) ^
                ((m - (m >> 7)) & 0xFF);
            tp9 = tp8 ^ tp1;
            tpb = tp9 ^ tp2;
            tpd = tp9 ^ tp4;
            tpe = tp8 ^ tp4 ^ tp2;
#if defined(ROTATE)
            t[i] = tpe ^ ROTATE(tpd,16) ^
                ROTATE(tp9,8) ^ ROTATE(tpb,24);
#else
            t[i] = tpe ^ (tpd >> 16) ^ (tpd << 16) ^
                (tp9 >> 24) ^ (tp9 << 8) ^
                (tpb >> 8) ^ (tpb << 24);
#endif
            t[i] ^= rk[i];
        }
    }
#else
    t[0] =  Td0[(s0      ) & 0xFF] ^
        Td1[(s3 >>  8) & 0xFF] ^
        Td2[(s2 >> 16) & 0xFF] ^
        Td3[(s1 >> 24)       ] ^
        rk[0];
    t[1] =  Td0[(s1      ) & 0xFF] ^
        Td1[(s0 >>  8) & 0xFF] ^
        Td2[(s3 >> 16) & 0xFF] ^
        Td3[(s2 >> 24)       ] ^
        rk[1];
    t[2] =  Td0[(s2      ) & 0xFF] ^
        Td1[(s1 >>  8) & 0xFF] ^
        Td2[(s0 >> 16) & 0xFF] ^
        Td3[(s3 >> 24)       ] ^
        rk[2];
    t[3] =  Td0[(s3      ) & 0xFF] ^
        Td1[(s2 >>  8) & 0xFF] ^
        Td2[(s1 >> 16) & 0xFF] ^
        Td3[(s0 >> 24)       ] ^
        rk[3];
#endif
    s0 = t[0]; s1 = t[1]; s2 = t[2]; s3 = t[3];
    }
    /*
     * apply last round and
     * map cipher state to byte array block:
     */
    prefetch256(Td4);

    *(u32*)(out+0) =
        ((u32)Td4[(s0      ) & 0xFF])    ^
        ((u32)Td4[(s3 >>  8) & 0xFF] <<  8) ^
        ((u32)Td4[(s2 >> 16) & 0xFF] << 16) ^
        ((u32)Td4[(s1 >> 24)       ] << 24) ^
        rk[0];
    *(u32*)(out+4) =
        ((u32)Td4[(s1      ) & 0xFF])     ^
        ((u32)Td4[(s0 >>  8) & 0xFF] <<  8) ^
        ((u32)Td4[(s3 >> 16) & 0xFF] << 16) ^
        ((u32)Td4[(s2 >> 24)       ] << 24) ^
        rk[1];
    *(u32*)(out+8) =
        ((u32)Td4[(s2      ) & 0xFF])     ^
        ((u32)Td4[(s1 >>  8) & 0xFF] <<  8) ^
        ((u32)Td4[(s0 >> 16) & 0xFF] << 16) ^
        ((u32)Td4[(s3 >> 24)       ] << 24) ^
        rk[2];
    *(u32*)(out+12) =
        ((u32)Td4[(s3      ) & 0xFF])     ^
        ((u32)Td4[(s2 >>  8) & 0xFF] <<  8) ^
        ((u32)Td4[(s1 >> 16) & 0xFF] << 16) ^
        ((u32)Td4[(s0 >> 24)       ] << 24) ^
        rk[3];
}
