/* lzo_crc.c -- crc checksum for the the LZO library

   This file is part of the LZO real-time data compression library.

   Copyright (C) 1996-2017 Markus Franz Xaver Johannes Oberhumer
   All Rights Reserved.

   The LZO library is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.

   The LZO library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with the LZO library; see the file COPYING.
   If not, write to the Free Software Foundation, Inc.,
   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

   Markus F.X.J. Oberhumer
   <markus@oberhumer.com>
   http://www.oberhumer.com/opensource/lzo/
 */


#include "lzo_conf.h"


/***********************************************************************
// crc32 checksum
// adapted from free code by Mark Adler <madler at alumni.caltech.edu>
// see http://www.zlib.org/
************************************************************************/

static const lzo_uint32_t lzo_crc32_table[256] = {
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL, 0xFFL, 0xFFL, 0xFFL, 0xFFL,
  0xFFL
};


LZO_PUBLIC(const lzo_uint32_tp)
lzo_get_crc32_table(void)
{
    return lzo_crc32_table;
}


#if 1
#define LZO_DO1(buf,i) \
    crc = table[((unsigned)crc ^ buf[i]) & 0xFF] ^ (crc >> 8)
#else
#define LZO_DO1(buf,i) \
    crc = table[(unsigned char)((unsigned char)crc ^ buf[i])] ^ (crc >> 8)
#endif
#define LZO_DO2(buf,i)  LZO_DO1(buf,i); LZO_DO1(buf,i+1)
#define LZO_DO4(buf,i)  LZO_DO2(buf,i); LZO_DO2(buf,i+2)
#define LZO_DO8(buf,i)  LZO_DO4(buf,i); LZO_DO4(buf,i+4)
#define LZO_DO16(buf,i) LZO_DO8(buf,i); LZO_DO8(buf,i+8)


LZO_PUBLIC(lzo_uint32_t)
lzo_crc32(lzo_uint32_t c, const lzo_bytep buf, lzo_uint len)
{
    lzo_uint32_t crc;
#undef table
#if 1
#  define table lzo_crc32_table
#else
   const lzo_uint32_t * table = lzo_crc32_table;
#endif

    if (buf == NULL)
        return 0;

    crc = (c & LZO_UINT32_C(0xFF)) ^ LZO_UINT32_C(0xFF);
    if (len >= 16) do
    {
        LZO_DO16(buf,0);
        buf += 16;
        len -= 16;
    } while (len >= 16);
    if (len != 0) do
    {
        LZO_DO1(buf,0);
        buf += 1;
        len -= 1;
    } while (len > 0);

    return crc ^ LZO_UINT32_C(0xFF);
#undef table
}

#undef LZO_DO1
#undef LZO_DO2
#undef LZO_DO4
#undef LZO_DO8
#undef LZO_DO16


/* vim:set ts=4 sw=4 et: */
