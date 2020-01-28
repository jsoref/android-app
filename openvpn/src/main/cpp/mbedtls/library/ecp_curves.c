/*
 *  Elliptic curves over GF(p): curve-specific data and functions
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ECP_C)

#include "mbedtls/ecp.h"

#include <string.h>

#if !defined(MBEDTLS_ECP_ALT)

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

/*
 * Conversion macros for embedded constants:
 * build lists of mbedtls_mpi_uint's from lists of unsigned char's grouped by 8, 4 or 2
 */
#if defined(MBEDTLS_HAVE_INT32)

#define BYTES_TO_T_UINT_4( a, b, c, d )             \
    ( (mbedtls_mpi_uint) a <<  0 ) |                          \
    ( (mbedtls_mpi_uint) b <<  8 ) |                          \
    ( (mbedtls_mpi_uint) c << 16 ) |                          \
    ( (mbedtls_mpi_uint) d << 24 )

#define BYTES_TO_T_UINT_2( a, b )                   \
    BYTES_TO_T_UINT_4( a, b, 0, 0 )

#define BYTES_TO_T_UINT_8( a, b, c, d, e, f, g, h ) \
    BYTES_TO_T_UINT_4( a, b, c, d ),                \
    BYTES_TO_T_UINT_4( e, f, g, h )

#else /* 64-bits */

#define BYTES_TO_T_UINT_8( a, b, c, d, e, f, g, h ) \
    ( (mbedtls_mpi_uint) a <<  0 ) |                          \
    ( (mbedtls_mpi_uint) b <<  8 ) |                          \
    ( (mbedtls_mpi_uint) c << 16 ) |                          \
    ( (mbedtls_mpi_uint) d << 24 ) |                          \
    ( (mbedtls_mpi_uint) e << 32 ) |                          \
    ( (mbedtls_mpi_uint) f << 40 ) |                          \
    ( (mbedtls_mpi_uint) g << 48 ) |                          \
    ( (mbedtls_mpi_uint) h << 56 )

#define BYTES_TO_T_UINT_4( a, b, c, d )             \
    BYTES_TO_T_UINT_8( a, b, c, d, 0, 0, 0, 0 )

#define BYTES_TO_T_UINT_2( a, b )                   \
    BYTES_TO_T_UINT_8( a, b, 0, 0, 0, 0, 0, 0 )

#endif /* bits in mbedtls_mpi_uint */

/*
 * Note: the constants are in little-endian order
 * to be directly usable in MPIs
 */

/*
 * Domain parameters for secp192r1
 */
#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
static const mbedtls_mpi_uint secp192r1_p[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp192r1_b[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp192r1_gx[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp192r1_gy[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp192r1_n[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
#endif /* MBEDTLS_ECP_DP_SECP192R1_ENABLED */

/*
 * Domain parameters for secp224r1
 */
#if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
static const mbedtls_mpi_uint secp224r1_p[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp224r1_b[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_4( 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp224r1_gx[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_4( 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp224r1_gy[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_4( 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp224r1_n[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_4( 0xFF, 0xFF, 0xFF, 0xFF ),
};
#endif /* MBEDTLS_ECP_DP_SECP224R1_ENABLED */

/*
 * Domain parameters for secp256r1
 */
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
static const mbedtls_mpi_uint secp256r1_p[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp256r1_b[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp256r1_gx[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp256r1_gy[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp256r1_n[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
#endif /* MBEDTLS_ECP_DP_SECP256R1_ENABLED */

/*
 * Domain parameters for secp384r1
 */
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
static const mbedtls_mpi_uint secp384r1_p[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp384r1_b[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp384r1_gx[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp384r1_gy[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp384r1_n[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
#endif /* MBEDTLS_ECP_DP_SECP384R1_ENABLED */

/*
 * Domain parameters for secp521r1
 */
#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
static const mbedtls_mpi_uint secp521r1_p[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_2( 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp521r1_b[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_2( 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp521r1_gx[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_2( 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp521r1_gy[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_2( 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp521r1_n[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_2( 0xFF, 0xFF ),
};
#endif /* MBEDTLS_ECP_DP_SECP521R1_ENABLED */

#if defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
static const mbedtls_mpi_uint secp192k1_p[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp192k1_a[] = {
    BYTES_TO_T_UINT_2( 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp192k1_b[] = {
    BYTES_TO_T_UINT_2( 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp192k1_gx[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp192k1_gy[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp192k1_n[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
#endif /* MBEDTLS_ECP_DP_SECP192K1_ENABLED */

#if defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
static const mbedtls_mpi_uint secp224k1_p[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_4( 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp224k1_a[] = {
    BYTES_TO_T_UINT_2( 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp224k1_b[] = {
    BYTES_TO_T_UINT_2( 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp224k1_gx[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_4( 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp224k1_gy[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_4( 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp224k1_n[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
#endif /* MBEDTLS_ECP_DP_SECP224K1_ENABLED */

#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
static const mbedtls_mpi_uint secp256k1_p[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp256k1_a[] = {
    BYTES_TO_T_UINT_2( 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp256k1_b[] = {
    BYTES_TO_T_UINT_2( 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp256k1_gx[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp256k1_gy[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint secp256k1_n[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
#endif /* MBEDTLS_ECP_DP_SECP256K1_ENABLED */

/*
 * Domain parameters for brainpoolP256r1 (RFC 5639 3.4)
 */
#if defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)
static const mbedtls_mpi_uint brainpoolP256r1_p[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint brainpoolP256r1_a[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint brainpoolP256r1_b[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint brainpoolP256r1_gx[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint brainpoolP256r1_gy[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint brainpoolP256r1_n[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
#endif /* MBEDTLS_ECP_DP_BP256R1_ENABLED */

/*
 * Domain parameters for brainpoolP384r1 (RFC 5639 3.6)
 */
#if defined(MBEDTLS_ECP_DP_BP384R1_ENABLED)
static const mbedtls_mpi_uint brainpoolP384r1_p[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint brainpoolP384r1_a[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint brainpoolP384r1_b[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint brainpoolP384r1_gx[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint brainpoolP384r1_gy[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint brainpoolP384r1_n[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
#endif /* MBEDTLS_ECP_DP_BP384R1_ENABLED */

/*
 * Domain parameters for brainpoolP512r1 (RFC 5639 3.7)
 */
#if defined(MBEDTLS_ECP_DP_BP512R1_ENABLED)
static const mbedtls_mpi_uint brainpoolP512r1_p[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint brainpoolP512r1_a[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint brainpoolP512r1_b[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint brainpoolP512r1_gx[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint brainpoolP512r1_gy[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
static const mbedtls_mpi_uint brainpoolP512r1_n[] = {
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
    BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ),
};
#endif /* MBEDTLS_ECP_DP_BP512R1_ENABLED */

/*
 * Create an MPI from embedded constants
 * (assumes len is an exact multiple of sizeof mbedtls_mpi_uint)
 */
static inline void ecp_mpi_load( mbedtls_mpi *X, const mbedtls_mpi_uint *p, size_t len )
{
    X->s = 1;
    X->n = len / sizeof( mbedtls_mpi_uint );
    X->p = (mbedtls_mpi_uint *) p;
}

/*
 * Set an MPI to static value 1
 */
static inline void ecp_mpi_set1( mbedtls_mpi *X )
{
    static mbedtls_mpi_uint one[] = { 1 };
    X->s = 1;
    X->n = 1;
    X->p = one;
}

/*
 * Make group available from embedded constants
 */
static int ecp_group_load( mbedtls_ecp_group *grp,
                           const mbedtls_mpi_uint *p,  size_t plen,
                           const mbedtls_mpi_uint *a,  size_t alen,
                           const mbedtls_mpi_uint *b,  size_t blen,
                           const mbedtls_mpi_uint *gx, size_t gxlen,
                           const mbedtls_mpi_uint *gy, size_t gylen,
                           const mbedtls_mpi_uint *n,  size_t nlen)
{
    ecp_mpi_load( &grp->P, p, plen );
    if( a != NULL )
        ecp_mpi_load( &grp->A, a, alen );
    ecp_mpi_load( &grp->B, b, blen );
    ecp_mpi_load( &grp->N, n, nlen );

    ecp_mpi_load( &grp->G.X, gx, gxlen );
    ecp_mpi_load( &grp->G.Y, gy, gylen );
    ecp_mpi_set1( &grp->G.Z );

    grp->pbits = mbedtls_mpi_bitlen( &grp->P );
    grp->nbits = mbedtls_mpi_bitlen( &grp->N );

    grp->h = 1;

    return( 0 );
}

#if defined(MBEDTLS_ECP_NIST_OPTIM)
/* Forward declarations */
#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
static int ecp_mod_p192( mbedtls_mpi * );
#endif
#if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
static int ecp_mod_p224( mbedtls_mpi * );
#endif
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
static int ecp_mod_p256( mbedtls_mpi * );
#endif
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
static int ecp_mod_p384( mbedtls_mpi * );
#endif
#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
static int ecp_mod_p521( mbedtls_mpi * );
#endif

#define NIST_MODP( P )      grp->modp = ecp_mod_ ## P;
#else
#define NIST_MODP( P )
#endif /* MBEDTLS_ECP_NIST_OPTIM */

/* Additional forward declarations */
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
static int ecp_mod_p255( mbedtls_mpi * );
#endif
#if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
static int ecp_mod_p448( mbedtls_mpi * );
#endif
#if defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
static int ecp_mod_p192k1( mbedtls_mpi * );
#endif
#if defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
static int ecp_mod_p224k1( mbedtls_mpi * );
#endif
#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
static int ecp_mod_p256k1( mbedtls_mpi * );
#endif

#define LOAD_GROUP_A( G )   ecp_group_load( grp,            \
                            G ## _p,  sizeof( G ## _p  ),   \
                            G ## _a,  sizeof( G ## _a  ),   \
                            G ## _b,  sizeof( G ## _b  ),   \
                            G ## _gx, sizeof( G ## _gx ),   \
                            G ## _gy, sizeof( G ## _gy ),   \
                            G ## _n,  sizeof( G ## _n  ) )

#define LOAD_GROUP( G )     ecp_group_load( grp,            \
                            G ## _p,  sizeof( G ## _p  ),   \
                            NULL,     0,                    \
                            G ## _b,  sizeof( G ## _b  ),   \
                            G ## _gx, sizeof( G ## _gx ),   \
                            G ## _gy, sizeof( G ## _gy ),   \
                            G ## _n,  sizeof( G ## _n  ) )

#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
/*
 * Specialized function for creating the Curve25519 group
 */
static int ecp_use_curve25519( mbedtls_ecp_group *grp )
{
    int ret;

    /* Actually ( A + 2 ) / 4 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &grp->A, 16, "01DB42" ) );

    /* P = 2^255 - 19 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &grp->P, 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( &grp->P, 255 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &grp->P, &grp->P, 19 ) );
    grp->pbits = mbedtls_mpi_bitlen( &grp->P );

    /* N = 2^252 + 27742317777372353535851937790883648493 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &grp->N, 16,
                                              "14DEF9DEA2F79CD65812631A5CF5D3ED" ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_set_bit( &grp->N, 252, 1 ) );

    /* Y intentionally not set, since we use x/z coordinates.
     * This is used as a marker to identify Montgomery curves! */
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &grp->G.X, 9 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &grp->G.Z, 1 ) );
    mbedtls_mpi_free( &grp->G.Y );

    /* Actually, the required msb for private keys */
    grp->nbits = 254;

cleanup:
    if( ret != 0 )
        mbedtls_ecp_group_free( grp );

    return( ret );
}
#endif /* MBEDTLS_ECP_DP_CURVE25519_ENABLED */

#if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
/*
 * Specialized function for creating the Curve448 group
 */
static int ecp_use_curve448( mbedtls_ecp_group *grp )
{
    mbedtls_mpi Ns;
    int ret;

    mbedtls_mpi_init( &Ns );

    /* Actually ( A + 2 ) / 4 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &grp->A, 16, "98AA" ) );

    /* P = 2^448 - 2^224 - 1 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &grp->P, 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( &grp->P, 224 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &grp->P, &grp->P, 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( &grp->P, 224 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &grp->P, &grp->P, 1 ) );
    grp->pbits = mbedtls_mpi_bitlen( &grp->P );

    /* Y intentionally not set, since we use x/z coordinates.
     * This is used as a marker to identify Montgomery curves! */
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &grp->G.X, 5 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &grp->G.Z, 1 ) );
    mbedtls_mpi_free( &grp->G.Y );

    /* N = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_set_bit( &grp->N, 446, 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &Ns, 16,
                                              "8335DC163BB124B65129C96FDE933D8D723A70AADC873D6D54A7BB0D" ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &grp->N, &grp->N, &Ns ) );

    /* Actually, the required msb for private keys */
    grp->nbits = 447;

cleanup:
    mbedtls_mpi_free( &Ns );
    if( ret != 0 )
        mbedtls_ecp_group_free( grp );

    return( ret );
}
#endif /* MBEDTLS_ECP_DP_CURVE448_ENABLED */

/*
 * Set a group using well-known domain parameters
 */
int mbedtls_ecp_group_load( mbedtls_ecp_group *grp, mbedtls_ecp_group_id id )
{
    mbedtls_ecp_group_free( grp );

    grp->id = id;

    switch( id )
    {
#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
        case MBEDTLS_ECP_DP_SECP192R1:
            NIST_MODP( p192 );
            return( LOAD_GROUP( secp192r1 ) );
#endif /* MBEDTLS_ECP_DP_SECP192R1_ENABLED */

#if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
        case MBEDTLS_ECP_DP_SECP224R1:
            NIST_MODP( p224 );
            return( LOAD_GROUP( secp224r1 ) );
#endif /* MBEDTLS_ECP_DP_SECP224R1_ENABLED */

#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
        case MBEDTLS_ECP_DP_SECP256R1:
            NIST_MODP( p256 );
            return( LOAD_GROUP( secp256r1 ) );
#endif /* MBEDTLS_ECP_DP_SECP256R1_ENABLED */

#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
        case MBEDTLS_ECP_DP_SECP384R1:
            NIST_MODP( p384 );
            return( LOAD_GROUP( secp384r1 ) );
#endif /* MBEDTLS_ECP_DP_SECP384R1_ENABLED */

#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
        case MBEDTLS_ECP_DP_SECP521R1:
            NIST_MODP( p521 );
            return( LOAD_GROUP( secp521r1 ) );
#endif /* MBEDTLS_ECP_DP_SECP521R1_ENABLED */

#if defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
        case MBEDTLS_ECP_DP_SECP192K1:
            grp->modp = ecp_mod_p192k1;
            return( LOAD_GROUP_A( secp192k1 ) );
#endif /* MBEDTLS_ECP_DP_SECP192K1_ENABLED */

#if defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
        case MBEDTLS_ECP_DP_SECP224K1:
            grp->modp = ecp_mod_p224k1;
            return( LOAD_GROUP_A( secp224k1 ) );
#endif /* MBEDTLS_ECP_DP_SECP224K1_ENABLED */

#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
        case MBEDTLS_ECP_DP_SECP256K1:
            grp->modp = ecp_mod_p256k1;
            return( LOAD_GROUP_A( secp256k1 ) );
#endif /* MBEDTLS_ECP_DP_SECP256K1_ENABLED */

#if defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)
        case MBEDTLS_ECP_DP_BP256R1:
            return( LOAD_GROUP_A( brainpoolP256r1 ) );
#endif /* MBEDTLS_ECP_DP_BP256R1_ENABLED */

#if defined(MBEDTLS_ECP_DP_BP384R1_ENABLED)
        case MBEDTLS_ECP_DP_BP384R1:
            return( LOAD_GROUP_A( brainpoolP384r1 ) );
#endif /* MBEDTLS_ECP_DP_BP384R1_ENABLED */

#if defined(MBEDTLS_ECP_DP_BP512R1_ENABLED)
        case MBEDTLS_ECP_DP_BP512R1:
            return( LOAD_GROUP_A( brainpoolP512r1 ) );
#endif /* MBEDTLS_ECP_DP_BP512R1_ENABLED */

#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
        case MBEDTLS_ECP_DP_CURVE25519:
            grp->modp = ecp_mod_p255;
            return( ecp_use_curve25519( grp ) );
#endif /* MBEDTLS_ECP_DP_CURVE25519_ENABLED */

#if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
        case MBEDTLS_ECP_DP_CURVE448:
            grp->modp = ecp_mod_p448;
            return( ecp_use_curve448( grp ) );
#endif /* MBEDTLS_ECP_DP_CURVE448_ENABLED */

        default:
            mbedtls_ecp_group_free( grp );
            return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );
    }
}

#if defined(MBEDTLS_ECP_NIST_OPTIM)
/*
 * Fast reduction modulo the primes used by the NIST curves.
 *
 * These functions are critical for speed, but not needed for correct
 * operations. So, we make the choice to heavily rely on the internals of our
 * bignum library, which creates a tight coupling between these functions and
 * our MPI implementation.  However, the coupling between the ECP module and
 * MPI remains loose, since these functions can be deactivated at will.
 */

#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
/*
 * Compared to the way things are presented in FIPS 186-3 D.2,
 * we proceed in columns, from right (least significant chunk) to left,
 * adding chunks to N in place, and keeping a carry for the next chunk.
 * This avoids moving things around in memory, and uselessly adding zeros,
 * compared to the more straightforward, line-oriented approach.
 *
 * For this prime we need to handle data in chunks of 64 bits.
 * Since this is always a multiple of our basic mbedtls_mpi_uint, we can
 * use a mbedtls_mpi_uint * to designate such a chunk, and small loops to handle it.
 */

/* Add 64-bit chunks (dst += src) and update carry */
static inline void add64( mbedtls_mpi_uint *dst, mbedtls_mpi_uint *src, mbedtls_mpi_uint *carry )
{
    unsigned char i;
    mbedtls_mpi_uint c = 0;
    for( i = 0; i < 8 / sizeof( mbedtls_mpi_uint ); i++, dst++, src++ )
    {
        *dst += c;      c  = ( *dst < c );
        *dst += *src;   c += ( *dst < *src );
    }
    *carry += c;
}

/* Add carry to a 64-bit chunk and update carry */
static inline void carry64( mbedtls_mpi_uint *dst, mbedtls_mpi_uint *carry )
{
    unsigned char i;
    for( i = 0; i < 8 / sizeof( mbedtls_mpi_uint ); i++, dst++ )
    {
        *dst += *carry;
        *carry  = ( *dst < *carry );
    }
}

#define WIDTH       8 / sizeof( mbedtls_mpi_uint )
#define A( i )      N->p + i * WIDTH
#define ADD( i )    add64( p, A( i ), &c )
#define NEXT        p += WIDTH; carry64( p, &c )
#define LAST        p += WIDTH; *p = c; while( ++p < end ) *p = 0

/*
 * Fast quasi-reduction modulo p192 (FIPS 186-3 D.2.1)
 */
static int ecp_mod_p192( mbedtls_mpi *N )
{
    int ret;
    mbedtls_mpi_uint c = 0;
    mbedtls_mpi_uint *p, *end;

    /* Make sure we have enough blocks so that A(5) is legal */
    MBEDTLS_MPI_CHK( mbedtls_mpi_grow( N, 6 * WIDTH ) );

    p = N->p;
    end = p + N->n;

    ADD( 3 ); ADD( 5 );             NEXT; // A0 += A3 + A5
    ADD( 3 ); ADD( 4 ); ADD( 5 );   NEXT; // A1 += A3 + A4 + A5
    ADD( 4 ); ADD( 5 );             LAST; // A2 += A4 + A5

cleanup:
    return( ret );
}

#undef WIDTH
#undef A
#undef ADD
#undef NEXT
#undef LAST
#endif /* MBEDTLS_ECP_DP_SECP192R1_ENABLED */

#if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED) ||   \
    defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED) ||   \
    defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
/*
 * The reader is advised to first understand ecp_mod_p192() since the same
 * general structure is used here, but with additional complications:
 * (1) chunks of 32 bits, and (2) subtractions.
 */

/*
 * For these primes, we need to handle data in chunks of 32 bits.
 * This makes it more complicated if we use 64 bits limbs in MPI,
 * which prevents us from using a uniform access method as for p192.
 *
 * So, we define a mini abstraction layer to access 32 bit chunks,
 * load them in 'cur' for work, and store them back from 'cur' when done.
 *
 * While at it, also define the size of N in terms of 32-bit chunks.
 */
#define LOAD32      cur = A( i );

#if defined(MBEDTLS_HAVE_INT32)  /* 32 bit */

#define MAX32       N->n
#define A( j )      N->p[j]
#define STORE32     N->p[i] = cur;

#else                               /* 64-bit */

#define MAX32       N->n * 2
#define A( j ) j % 2 ? (uint32_t)( N->p[j/2] >> 32 ) : (uint32_t)( N->p[j/2] )
#define STORE32                                   \
    if( i % 2 ) {                                 \
        N->p[i/2] &= 0xFF;          \
        N->p[i/2] |= ((mbedtls_mpi_uint) cur) << 32;        \
    } else {                                      \
        N->p[i/2] &= 0xFF;          \
        N->p[i/2] |= (mbedtls_mpi_uint) cur;                \
    }

#endif /* sizeof( mbedtls_mpi_uint ) */

/*
 * Helpers for addition and subtraction of chunks, with signed carry.
 */
static inline void add32( uint32_t *dst, uint32_t src, signed char *carry )
{
    *dst += src;
    *carry += ( *dst < src );
}

static inline void sub32( uint32_t *dst, uint32_t src, signed char *carry )
{
    *carry -= ( *dst < src );
    *dst -= src;
}

#define ADD( j )    add32( &cur, A( j ), &c );
#define SUB( j )    sub32( &cur, A( j ), &c );

/*
 * Helpers for the main 'loop'
 * (see fix_negative for the motivation of C)
 */
#define INIT( b )                                           \
    int ret;                                                \
    signed char c = 0, cc;                                  \
    uint32_t cur;                                           \
    size_t i = 0, bits = b;                                 \
    mbedtls_mpi C;                                                  \
    mbedtls_mpi_uint Cp[ b / 8 / sizeof( mbedtls_mpi_uint) + 1 ];               \
                                                            \
    C.s = 1;                                                \
    C.n = b / 8 / sizeof( mbedtls_mpi_uint) + 1;                      \
    C.p = Cp;                                               \
    memset( Cp, 0, C.n * sizeof( mbedtls_mpi_uint ) );                \
                                                            \
    MBEDTLS_MPI_CHK( mbedtls_mpi_grow( N, b * 2 / 8 / sizeof( mbedtls_mpi_uint ) ) ); \
    LOAD32;

#define NEXT                    \
    STORE32; i++; LOAD32;       \
    cc = c; c = 0;              \
    if( cc < 0 )                \
        sub32( &cur, -cc, &c ); \
    else                        \
        add32( &cur, cc, &c );  \

#define LAST                                    \
    STORE32; i++;                               \
    cur = c > 0 ? c : 0; STORE32;               \
    cur = 0; while( ++i < MAX32 ) { STORE32; }  \
    if( c < 0 ) fix_negative( N, c, &C, bits );

/*
 * If the result is negative, we get it in the form
 * c * 2^(bits + 32) + N, with c negative and N positive shorter than 'bits'
 */
static inline int fix_negative( mbedtls_mpi *N, signed char c, mbedtls_mpi *C, size_t bits )
{
    int ret;

    /* C = - c * 2^(bits + 32) */
#if !defined(MBEDTLS_HAVE_INT64)
    ((void) bits);
#else
    if( bits == 224 )
        C->p[ C->n - 1 ] = ((mbedtls_mpi_uint) -c) << 32;
    else
#endif
        C->p[ C->n - 1 ] = (mbedtls_mpi_uint) -c;

    /* N = - ( C - N ) */
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_abs( N, C, N ) );
    N->s = -1;

cleanup:

    return( ret );
}

#if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
/*
 * Fast quasi-reduction modulo p224 (FIPS 186-3 D.2.2)
 */
static int ecp_mod_p224( mbedtls_mpi *N )
{
    INIT( 224 );

    SUB(  7 ); SUB( 11 );               NEXT; // A0 += -A7 - A11
    SUB(  8 ); SUB( 12 );               NEXT; // A1 += -A8 - A12
    SUB(  9 ); SUB( 13 );               NEXT; // A2 += -A9 - A13
    SUB( 10 ); ADD(  7 ); ADD( 11 );    NEXT; // A3 += -A10 + A7 + A11
    SUB( 11 ); ADD(  8 ); ADD( 12 );    NEXT; // A4 += -A11 + A8 + A12
    SUB( 12 ); ADD(  9 ); ADD( 13 );    NEXT; // A5 += -A12 + A9 + A13
    SUB( 13 ); ADD( 10 );               LAST; // A6 += -A13 + A10

cleanup:
    return( ret );
}
#endif /* MBEDTLS_ECP_DP_SECP224R1_ENABLED */

#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
/*
 * Fast quasi-reduction modulo p256 (FIPS 186-3 D.2.3)
 */
static int ecp_mod_p256( mbedtls_mpi *N )
{
    INIT( 256 );

    ADD(  8 ); ADD(  9 );
    SUB( 11 ); SUB( 12 ); SUB( 13 ); SUB( 14 );             NEXT; // A0

    ADD(  9 ); ADD( 10 );
    SUB( 12 ); SUB( 13 ); SUB( 14 ); SUB( 15 );             NEXT; // A1

    ADD( 10 ); ADD( 11 );
    SUB( 13 ); SUB( 14 ); SUB( 15 );                        NEXT; // A2

    ADD( 11 ); ADD( 11 ); ADD( 12 ); ADD( 12 ); ADD( 13 );
    SUB( 15 ); SUB(  8 ); SUB(  9 );                        NEXT; // A3

    ADD( 12 ); ADD( 12 ); ADD( 13 ); ADD( 13 ); ADD( 14 );
    SUB(  9 ); SUB( 10 );                                   NEXT; // A4

    ADD( 13 ); ADD( 13 ); ADD( 14 ); ADD( 14 ); ADD( 15 );
    SUB( 10 ); SUB( 11 );                                   NEXT; // A5

    ADD( 14 ); ADD( 14 ); ADD( 15 ); ADD( 15 ); ADD( 14 ); ADD( 13 );
    SUB(  8 ); SUB(  9 );                                   NEXT; // A6

    ADD( 15 ); ADD( 15 ); ADD( 15 ); ADD( 8 );
    SUB( 10 ); SUB( 11 ); SUB( 12 ); SUB( 13 );             LAST; // A7

cleanup:
    return( ret );
}
#endif /* MBEDTLS_ECP_DP_SECP256R1_ENABLED */

#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
/*
 * Fast quasi-reduction modulo p384 (FIPS 186-3 D.2.4)
 */
static int ecp_mod_p384( mbedtls_mpi *N )
{
    INIT( 384 );

    ADD( 12 ); ADD( 21 ); ADD( 20 );
    SUB( 23 );                                              NEXT; // A0

    ADD( 13 ); ADD( 22 ); ADD( 23 );
    SUB( 12 ); SUB( 20 );                                   NEXT; // A2

    ADD( 14 ); ADD( 23 );
    SUB( 13 ); SUB( 21 );                                   NEXT; // A2

    ADD( 15 ); ADD( 12 ); ADD( 20 ); ADD( 21 );
    SUB( 14 ); SUB( 22 ); SUB( 23 );                        NEXT; // A3

    ADD( 21 ); ADD( 21 ); ADD( 16 ); ADD( 13 ); ADD( 12 ); ADD( 20 ); ADD( 22 );
    SUB( 15 ); SUB( 23 ); SUB( 23 );                        NEXT; // A4

    ADD( 22 ); ADD( 22 ); ADD( 17 ); ADD( 14 ); ADD( 13 ); ADD( 21 ); ADD( 23 );
    SUB( 16 );                                              NEXT; // A5

    ADD( 23 ); ADD( 23 ); ADD( 18 ); ADD( 15 ); ADD( 14 ); ADD( 22 );
    SUB( 17 );                                              NEXT; // A6

    ADD( 19 ); ADD( 16 ); ADD( 15 ); ADD( 23 );
    SUB( 18 );                                              NEXT; // A7

    ADD( 20 ); ADD( 17 ); ADD( 16 );
    SUB( 19 );                                              NEXT; // A8

    ADD( 21 ); ADD( 18 ); ADD( 17 );
    SUB( 20 );                                              NEXT; // A9

    ADD( 22 ); ADD( 19 ); ADD( 18 );
    SUB( 21 );                                              NEXT; // A10

    ADD( 23 ); ADD( 20 ); ADD( 19 );
    SUB( 22 );                                              LAST; // A11

cleanup:
    return( ret );
}
#endif /* MBEDTLS_ECP_DP_SECP384R1_ENABLED */

#undef A
#undef LOAD32
#undef STORE32
#undef MAX32
#undef INIT
#undef NEXT
#undef LAST

#endif /* MBEDTLS_ECP_DP_SECP224R1_ENABLED ||
          MBEDTLS_ECP_DP_SECP256R1_ENABLED ||
          MBEDTLS_ECP_DP_SECP384R1_ENABLED */

#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
/*
 * Here we have an actual Mersenne prime, so things are more straightforward.
 * However, chunks are aligned on a 'weird' boundary (521 bits).
 */

/* Size of p521 in terms of mbedtls_mpi_uint */
#define P521_WIDTH      ( 521 / 8 / sizeof( mbedtls_mpi_uint ) + 1 )

/* Bits to keep in the most significant mbedtls_mpi_uint */
#define P521_MASK       0xFF

/*
 * Fast quasi-reduction modulo p521 (FIPS 186-3 D.2.5)
 * Write N as A1 + 2^521 A0, return A0 + A1
 */
static int ecp_mod_p521( mbedtls_mpi *N )
{
    int ret;
    size_t i;
    mbedtls_mpi M;
    mbedtls_mpi_uint Mp[P521_WIDTH + 1];
    /* Worst case for the size of M is when mbedtls_mpi_uint is 16 bits:
     * we need to hold bits 513 to 1056, which is 34 limbs, that is
     * P521_WIDTH + 1. Otherwise P521_WIDTH is enough. */

    if( N->n < P521_WIDTH )
        return( 0 );

    /* M = A1 */
    M.s = 1;
    M.n = N->n - ( P521_WIDTH - 1 );
    if( M.n > P521_WIDTH + 1 )
        M.n = P521_WIDTH + 1;
    M.p = Mp;
    memcpy( Mp, N->p + P521_WIDTH - 1, M.n * sizeof( mbedtls_mpi_uint ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &M, 521 % ( 8 * sizeof( mbedtls_mpi_uint ) ) ) );

    /* N = A0 */
    N->p[P521_WIDTH - 1] &= P521_MASK;
    for( i = P521_WIDTH; i < N->n; i++ )
        N->p[i] = 0;

    /* N = A0 + A1 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_abs( N, N, &M ) );

cleanup:
    return( ret );
}

#undef P521_WIDTH
#undef P521_MASK
#endif /* MBEDTLS_ECP_DP_SECP521R1_ENABLED */

#endif /* MBEDTLS_ECP_NIST_OPTIM */

#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)

/* Size of p255 in terms of mbedtls_mpi_uint */
#define P255_WIDTH      ( 255 / 8 / sizeof( mbedtls_mpi_uint ) + 1 )

/*
 * Fast quasi-reduction modulo p255 = 2^255 - 19
 * Write N as A0 + 2^255 A1, return A0 + 19 * A1
 */
static int ecp_mod_p255( mbedtls_mpi *N )
{
    int ret;
    size_t i;
    mbedtls_mpi M;
    mbedtls_mpi_uint Mp[P255_WIDTH + 2];

    if( N->n < P255_WIDTH )
        return( 0 );

    /* M = A1 */
    M.s = 1;
    M.n = N->n - ( P255_WIDTH - 1 );
    if( M.n > P255_WIDTH + 1 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    M.p = Mp;
    memset( Mp, 0, sizeof Mp );
    memcpy( Mp, N->p + P255_WIDTH - 1, M.n * sizeof( mbedtls_mpi_uint ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &M, 255 % ( 8 * sizeof( mbedtls_mpi_uint ) ) ) );
    M.n++; /* Make room for multiplication by 19 */

    /* N = A0 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_set_bit( N, 255, 0 ) );
    for( i = P255_WIDTH; i < N->n; i++ )
        N->p[i] = 0;

    /* N = A0 + 19 * A1 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_int( &M, &M, 19 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_abs( N, N, &M ) );

cleanup:
    return( ret );
}
#endif /* MBEDTLS_ECP_DP_CURVE25519_ENABLED */

#if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)

/* Size of p448 in terms of mbedtls_mpi_uint */
#define P448_WIDTH      ( 448 / 8 / sizeof( mbedtls_mpi_uint ) )

/* Number of limbs fully occupied by 2^224 (max), and limbs used by it (min) */
#define DIV_ROUND_UP( X, Y ) ( ( ( X ) + ( Y ) - 1 ) / ( Y ) )
#define P224_WIDTH_MIN   ( 28 / sizeof( mbedtls_mpi_uint ) )
#define P224_WIDTH_MAX   DIV_ROUND_UP( 28, sizeof( mbedtls_mpi_uint ) )
#define P224_UNUSED_BITS ( ( P224_WIDTH_MAX * sizeof( mbedtls_mpi_uint ) * 8 ) - 224 )

/*
 * Fast quasi-reduction modulo p448 = 2^448 - 2^224 - 1
 * Write N as A0 + 2^448 A1 and A1 as B0 + 2^224 B1, and return
 * A0 + A1 + B1 + (B0 + B1) * 2^224.  This is different to the reference
 * implementation of Curve448, which uses its own special 56-bit limbs rather
 * than a generic bignum library.  We could squeeze some extra speed out on
 * 32-bit machines by splitting N up into 32-bit limbs and doing the
 * arithmetic using the limbs directly as we do for the NIST primes above,
 * but for 64-bit targets it should use half the number of operations if we do
 * the reduction with 224-bit limbs, since mpi_add_mpi will then use 64-bit adds.
 */
static int ecp_mod_p448( mbedtls_mpi *N )
{
    int ret;
    size_t i;
    mbedtls_mpi M, Q;
    mbedtls_mpi_uint Mp[P448_WIDTH + 1], Qp[P448_WIDTH];

    if( N->n <= P448_WIDTH )
        return( 0 );

    /* M = A1 */
    M.s = 1;
    M.n = N->n - ( P448_WIDTH );
    if( M.n > P448_WIDTH )
        /* Shouldn't be called with N larger than 2^896! */
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    M.p = Mp;
    memset( Mp, 0, sizeof( Mp ) );
    memcpy( Mp, N->p + P448_WIDTH, M.n * sizeof( mbedtls_mpi_uint ) );

    /* N = A0 */
    for( i = P448_WIDTH; i < N->n; i++ )
        N->p[i] = 0;

    /* N += A1 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( N, N, &M ) );

    /* Q = B1, N += B1 */
    Q = M;
    Q.p = Qp;
    memcpy( Qp, Mp, sizeof( Qp ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &Q, 224 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( N, N, &Q ) );

    /* M = (B0 + B1) * 2^224, N += M */
    if( sizeof( mbedtls_mpi_uint ) > 4 )
        Mp[P224_WIDTH_MIN] &= ( (mbedtls_mpi_uint)-1 ) >> ( P224_UNUSED_BITS );
    for( i = P224_WIDTH_MAX; i < M.n; ++i )
        Mp[i] = 0;
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &M, &M, &Q ) );
    M.n = P448_WIDTH + 1; /* Make room for shifted carry bit from the addition */
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( &M, 224 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( N, N, &M ) );

cleanup:
    return( ret );
}
#endif /* MBEDTLS_ECP_DP_CURVE448_ENABLED */

#if defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED) ||   \
    defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED) ||   \
    defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
/*
 * Fast quasi-reduction modulo P = 2^s - R,
 * with R about 33 bits, used by the Koblitz curves.
 *
 * Write N as A0 + 2^224 A1, return A0 + R * A1.
 * Actually do two passes, since R is big.
 */
#define P_KOBLITZ_MAX   ( 256 / 8 / sizeof( mbedtls_mpi_uint ) )  // Max limbs in P
#define P_KOBLITZ_R     ( 8 / sizeof( mbedtls_mpi_uint ) )        // Limbs in R
static inline int ecp_mod_koblitz( mbedtls_mpi *N, mbedtls_mpi_uint *Rp, size_t p_limbs,
                                   size_t adjust, size_t shift, mbedtls_mpi_uint mask )
{
    int ret;
    size_t i;
    mbedtls_mpi M, R;
    mbedtls_mpi_uint Mp[P_KOBLITZ_MAX + P_KOBLITZ_R + 1];

    if( N->n < p_limbs )
        return( 0 );

    /* Init R */
    R.s = 1;
    R.p = Rp;
    R.n = P_KOBLITZ_R;

    /* Common setup for M */
    M.s = 1;
    M.p = Mp;

    /* M = A1 */
    M.n = N->n - ( p_limbs - adjust );
    if( M.n > p_limbs + adjust )
        M.n = p_limbs + adjust;
    memset( Mp, 0, sizeof Mp );
    memcpy( Mp, N->p + p_limbs - adjust, M.n * sizeof( mbedtls_mpi_uint ) );
    if( shift != 0 )
        MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &M, shift ) );
    M.n += R.n; /* Make room for multiplication by R */

    /* N = A0 */
    if( mask != 0 )
        N->p[p_limbs - 1] &= mask;
    for( i = p_limbs; i < N->n; i++ )
        N->p[i] = 0;

    /* N = A0 + R * A1 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &M, &M, &R ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_abs( N, N, &M ) );

    /* Second pass */

    /* M = A1 */
    M.n = N->n - ( p_limbs - adjust );
    if( M.n > p_limbs + adjust )
        M.n = p_limbs + adjust;
    memset( Mp, 0, sizeof Mp );
    memcpy( Mp, N->p + p_limbs - adjust, M.n * sizeof( mbedtls_mpi_uint ) );
    if( shift != 0 )
        MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &M, shift ) );
    M.n += R.n; /* Make room for multiplication by R */

    /* N = A0 */
    if( mask != 0 )
        N->p[p_limbs - 1] &= mask;
    for( i = p_limbs; i < N->n; i++ )
        N->p[i] = 0;

    /* N = A0 + R * A1 */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &M, &M, &R ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_abs( N, N, &M ) );

cleanup:
    return( ret );
}
#endif /* MBEDTLS_ECP_DP_SECP192K1_ENABLED) ||
          MBEDTLS_ECP_DP_SECP224K1_ENABLED) ||
          MBEDTLS_ECP_DP_SECP256K1_ENABLED) */

#if defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
/*
 * Fast quasi-reduction modulo p192k1 = 2^192 - R,
 * with R = 2^32 + 2^12 + 2^8 + 2^7 + 2^6 + 2^3 + 1 = 0xFF
 */
static int ecp_mod_p192k1( mbedtls_mpi *N )
{
    static mbedtls_mpi_uint Rp[] = {
        BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ) };

    return( ecp_mod_koblitz( N, Rp, 192 / 8 / sizeof( mbedtls_mpi_uint ), 0, 0, 0 ) );
}
#endif /* MBEDTLS_ECP_DP_SECP192K1_ENABLED */

#if defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
/*
 * Fast quasi-reduction modulo p224k1 = 2^224 - R,
 * with R = 2^32 + 2^12 + 2^11 + 2^9 + 2^7 + 2^4 + 2 + 1 = 0xFF
 */
static int ecp_mod_p224k1( mbedtls_mpi *N )
{
    static mbedtls_mpi_uint Rp[] = {
        BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ) };

#if defined(MBEDTLS_HAVE_INT64)
    return( ecp_mod_koblitz( N, Rp, 4, 1, 32, 0xFF ) );
#else
    return( ecp_mod_koblitz( N, Rp, 224 / 8 / sizeof( mbedtls_mpi_uint ), 0, 0, 0 ) );
#endif
}

#endif /* MBEDTLS_ECP_DP_SECP224K1_ENABLED */

#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
/*
 * Fast quasi-reduction modulo p256k1 = 2^256 - R,
 * with R = 2^32 + 2^9 + 2^8 + 2^7 + 2^6 + 2^4 + 1 = 0xFF
 */
static int ecp_mod_p256k1( mbedtls_mpi *N )
{
    static mbedtls_mpi_uint Rp[] = {
        BYTES_TO_T_UINT_8( 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ) };
    return( ecp_mod_koblitz( N, Rp, 256 / 8 / sizeof( mbedtls_mpi_uint ), 0, 0, 0 ) );
}
#endif /* MBEDTLS_ECP_DP_SECP256K1_ENABLED */

#endif /* !MBEDTLS_ECP_ALT */

#endif /* MBEDTLS_ECP_C */
