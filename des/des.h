/*
 * des.h
 * 12/Aug/2012
 * Author: Evan Dempsey <evandempsey@gmail.com>
 */

#ifndef DES_H_INCLUDED
#define DES_H_INCLUDED

#include <stdio.h>
#include <stdint.h>

#include "des_block.h"

extern const int PC1[];
extern const int PC2[];

uint32_t rotate_half_key(uint32_t half_key);
des_block_t permute(des_block_t key, const int* table, uint32_t src_len, uint32_t dest_len);
des_block_t permute_pc1(des_block_t key);
des_block_t* permute_pc2(des_block_t* shifted_subkeys);
des_block_t initial_permutation(des_block_t block);
des_block_t final_permutation(des_block_t block);
des_block_t permute_e(des_block_t block);
des_block_t permute_p(des_block_t block);
des_block_t* shift_subkeys(des_block_t permuted);
des_block_t* generate_key_schedule(des_block_t passphrase);
uint32_t lookup_sbox(uint32_t group, uint32_t sbox);
des_block_t sbox_transform(des_block_t block);
uint32_t feistel(uint32_t right_block, des_block_t key);
des_block_t encode_round(des_block_t block, des_block_t key);
des_block_t encode_block(des_block_t block, des_block_t* schedule, uint32_t direction);
des_block_t make_block(int32_t *chars);
des_block_t get_passphrase();
void write_block(FILE *output, des_block_t block, int32_t padding);
void encrypt(FILE *input, FILE *output, des_block_t *key_schedule);
void decrypt(FILE *input, FILE *output, des_block_t *key_schedule);
void print_help(void);

#endif
