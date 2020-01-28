/*
 * Copyright 1998-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* NOCW */
#include <stdio.h>
#ifdef _OSD_POSIX
# ifndef CHARSET_EBCDIC
#  define CHARSET_EBCDIC 1
# endif
#endif
#ifdef CHARSET_EBCDIC
# include <openssl/ebcdic.h>
#endif

#include <openssl/crypto.h>
#include "des_locl.h"

/*
 * Added more values to handle illegal salt values the way normal crypt()
 * implementations do.
 */
static unsigned const char con_salt[128] = {
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
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static unsigned const char cov_2char[64] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

char *DES_crypt(const char *buf, const char *salt)
{
    static char buff[14];

#ifndef CHARSET_EBCDIC
    return DES_fcrypt(buf, salt, buff);
#else
    char e_salt[2 + 1];
    char e_buf[32 + 1];         /* replace 32 by 8 ? */
    char *ret;

    if (salt[0] == '\0' || salt[1] == '\0')
        return NULL;

    /* Copy salt, convert to ASCII. */
    e_salt[0] = salt[0];
    e_salt[1] = salt[1];
    e_salt[2] = '\0';
    ebcdic2ascii(e_salt, e_salt, sizeof(e_salt));

    /* Convert password to ASCII. */
    OPENSSL_strlcpy(e_buf, buf, sizeof(e_buf));
    ebcdic2ascii(e_buf, e_buf, sizeof(e_buf));

    /* Encrypt it (from/to ASCII); if it worked, convert back. */
    ret = DES_fcrypt(e_buf, e_salt, buff);
    if (ret != NULL)
        ascii2ebcdic(ret, ret, strlen(ret));

    return ret;
#endif
}

char *DES_fcrypt(const char *buf, const char *salt, char *ret)
{
    unsigned int i, j, x, y;
    DES_LONG Eswap0, Eswap1;
    DES_LONG out[2], ll;
    DES_cblock key;
    DES_key_schedule ks;
    unsigned char bb[9];
    unsigned char *b = bb;
    unsigned char c, u;

    x = ret[0] = salt[0];
    if (x == 0 || x >= sizeof(con_salt))
        return NULL;
    Eswap0 = con_salt[x] << 2;
    x = ret[1] = salt[1];
    if (x == 0 || x >= sizeof(con_salt))
        return NULL;
    Eswap1 = con_salt[x] << 6;

    /*
     * EAY r=strlen(buf); r=(r+7)/8;
     */
    for (i = 0; i < 8; i++) {
        c = *(buf++);
        if (!c)
            break;
        key[i] = (c << 1);
    }
    for (; i < 8; i++)
        key[i] = 0;

    DES_set_key_unchecked(&key, &ks);
    fcrypt_body(&(out[0]), &ks, Eswap0, Eswap1);

    ll = out[0];
    l2c(ll, b);
    ll = out[1];
    l2c(ll, b);
    y = 0;
    u = 0xFF;
    bb[8] = 0;
    for (i = 2; i < 13; i++) {
        c = 0;
        for (j = 0; j < 6; j++) {
            c <<= 1;
            if (bb[y] & u)
                c |= 1;
            u >>= 1;
            if (!u) {
                y++;
                u = 0xFF;
            }
        }
        ret[i] = cov_2char[c];
    }
    ret[13] = '\0';
    return ret;
}
