/*
 * test.c
 * 12/Aug/2012
 * Author: Evan Dempsey <evandempsey@gmail.com>
 */

#include <stdlib.h>
#include <assert.h>
#include "des.h"

void test_permute_pc1()
{
	des_block_t key;
	key.c = 0x13345779;
	key.d = 0x9BBCDFF1;
	des_block_t des_key = permute_pc1(key);
	assert(des_key.c == 0xF0CCAAF);
	assert(des_key.d == 0x556678F);
}

void test_permute_pc2()
{
	des_block_t key;
    key.c = 0xE19955F;
    key.d = 0xAACCF1E;
	des_block_t pc2 = permute(key, PC2, PC1LENGTH, PC2LENGTH);
    assert(pc2.c == 0x1B02EF);
    assert(pc2.d == 0xFC7072);
}

void test_permute()
{
	des_block_t block;
	block.c = 0x13345779;
	block.d = 0x9BBCDFF1;
	des_block_t pc1 = permute(block, PC1, KEYLENGTH, PC1LENGTH);
	assert(pc1.c == 0xF0CCAAF);
	assert(pc1.d == 0x556678F);
}

void test_rotate_half_key()
{
	uint32_t rotated_key = rotate_half_key(0xF0CCAAF);
	assert(rotated_key == 0xE19955F);
}

void test_shift_subkeys()
{
	des_block_t des_key;
	des_key.c = 0xF0CCAAF;
	des_key.d = 0x556678F;
	des_block_t* shifted_subkeys = shift_subkeys(des_key);
	assert(shifted_subkeys[0].c == 0xE19955F);
	assert(shifted_subkeys[0].d == 0xAACCF1E);
	assert(shifted_subkeys[1].c == 0xC332ABF);
	assert(shifted_subkeys[1].d == 0x5599E3D);
	assert(shifted_subkeys[15].c == 0xF0CCAAF);
	assert(shifted_subkeys[15].d == 0x556678F);
	free(shifted_subkeys);
}

void test_generate_key_schedule()
{
	des_block_t key;
	key.c = 0x13345779;
	key.d = 0x9BBCDFF1;
	des_block_t* key_schedule = generate_key_schedule(key);
	assert(key_schedule[0].c == 0x1B02EF);
	assert(key_schedule[0].d == 0xFC7072);
	assert(key_schedule[15].c == 0xCB3D8B);
	assert(key_schedule[15].d == 0x0E17F5);
}

void test_initial_permutation()
{
	des_block_t mblock;
	mblock.c = 0x01234567;
	mblock.d = 0x89ABCDEF;
	des_block_t ip = initial_permutation(mblock);
	assert(ip.c == 0xCC00CCFF);
	assert(ip.d == 0xF0AAF0AA);
}

void test_permute_e()
{
	des_block_t half_block;
	half_block.c = 0xF0AA;
	half_block.d = 0xF0AA;
	des_block_t ep = permute_e(half_block);
	assert(ep.c == 0x7A1555);
	assert(ep.d == 0x7A1555);
}

void test_sbox_transform()
{
	des_block_t xor;
	xor.c = 0x6117BA;
	xor.d = 0x866527;
	des_block_t sbox = sbox_transform(xor);
	assert(sbox.c == 0x5C82);
	assert(sbox.d == 0xB597);
}

void test_block_encode()
{
	des_block_t key;
	key.c = 0x13345779;
	key.d = 0x9BBCDFF1;
	des_block_t* key_schedule = generate_key_schedule(key);

	des_block_t message_block;
	message_block.c = 0x01234567;
	message_block.d = 0x89ABCDEF;
	des_block_t encoded = encode_block(message_block, key_schedule, ENCODE);
	assert(encoded.c == 0x85E81354);
	assert(encoded.d == 0x0F0AB405);

	free(key_schedule);
}

void test_block_decode()
{
	des_block_t key;
	key.c = 0x13345779;
	key.d = 0x9BBCDFF1;
	des_block_t* key_schedule = generate_key_schedule(key);

	des_block_t message_block;
	message_block.c = 0x01234567;
	message_block.d = 0x89ABCDEF;
	des_block_t decoded = encode_block(message_block, key_schedule, DECODE);
	assert(decoded.c == 0xEE0F7C12);
	assert(decoded.d == 0xE0B09338);

	free(key_schedule);
}

void test() {
	test_permute_pc1();
	test_permute_pc2();
	test_permute();
	test_rotate_half_key();
	test_shift_subkeys();
	test_generate_key_schedule();
	test_initial_permutation();
	test_permute_e();
	test_sbox_transform();
	test_block_encode();
	test_block_decode();

    printf("All tests passed.\n");
}
