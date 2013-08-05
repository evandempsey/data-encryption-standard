/*
 * des_block.h
 * 05/Aug/2013
 * Author: Evan Dempsey <evandempsey@gmail.com>
 */

#ifndef DES_BLOCK_H_INCLUDED
#define DES_BLOCK_H_INCLUDED

#include <stdint.h>

#define KEYLENGTH 64
#define BLOCKLENGTH 64
#define PC1LENGTH 56
#define PC2LENGTH 48
#define ELENGTH 48
#define PLENGTH 32
#define INVERSEIPLENGTH 64
#define NUMSUBKEYS 16
#define INTWIDTH 32
#define ENCODE 1
#define DECODE 0

struct des_block {
    uint32_t c;
    uint32_t d;
} typedef des_block_t;

#endif
