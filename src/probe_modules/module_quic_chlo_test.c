/*
 * Jean-Pierre Smith 2019
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 */

/* Test module for GQUIC enumeration via module_quic_chlo */
#include <stdlib.h>
#include <endian.h>
#include <assert.h>
#include <string.h>

#include "unity.h"
#include "probe_modules/module_quic_chlo.h"

void test_make_uint32_tag(void)
{
	tag_info tag = make_uint32_tag("MIDS", 100);

	TEST_ASSERT_EQUAL_STRING_LEN("MIDS", tag.type, 4);
	TEST_ASSERT_EQUAL(4, tag.value_len);
	TEST_ASSERT_EQUAL_HEX8_ARRAY("\x64\0\0\0", tag.value, 4);

	free_tag_info(&tag);
}

void test_make_raw_tags_no_data(void)
{
	tag_info tag = make_raw_tag("CSCT", NULL, 0);

	TEST_ASSERT_EQUAL_STRING_LEN("CSCT", tag.type, 4);
	TEST_ASSERT_EQUAL(0, tag.value_len);

	free_tag_info(&tag);
}

void test_make_raw_tag(void)
{
	tag_info tag = make_raw_tag("CCS", "HELLO GOOD WORLD", 16);

	TEST_ASSERT_EQUAL_STRING_LEN("CCS\0", tag.type, 4);
	TEST_ASSERT_EQUAL(16, tag.value_len);
	TEST_ASSERT_EQUAL_HEX8_ARRAY("HELLO GOOD WORLD", tag.value, 16);

	free_tag_info(&tag);
}

void test_make_pad_tag(void)
{
	tag_info tag = make_pad_tag(999);

	TEST_ASSERT_EQUAL_STRING_LEN("PAD\0", tag.type, 4);
	TEST_ASSERT_EQUAL(999, tag.value_len);
	TEST_ASSERT_EACH_EQUAL_HEX8(0x2d, tag.value, 999);

	free_tag_info(&tag);
}

void test_pack_tags(void)
{
	uint8_t buffer[100];
	uint8_t expected[42] = {
	    'P',  'A',  'D',  0x00, 0x0a, 0x00, 0x00, 0x00, //
	    'V',  'E',  'R',  0x00, 0x0e, 0x00, 0x00, 0x00, //
	    'M',  'I',  'D',  'S',  0x12, 0x00, 0x00, 0x00, //
	    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, //
	    0x2d, 0x2d, 'Q',  '0',  '4',  '3',  0x64, 0x00, //
	    0x00, 0x00};

	tag_info tags[3] = {make_pad_tag(10), make_raw_tag("VER", "Q043", 4),
			    make_uint32_tag("MIDS", 100)};

	int write_count = pack_tags(tags, 3, buffer, 100);

	TEST_ASSERT_EQUAL(42, write_count);
	TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, buffer, write_count);
}

// void test_write_chlo_stream_frame(void)
// {
// 	uint8_t buffer[100];
// 	uint8_t expected[36] = {
// 	    0xa0, 0x01, 0x20, 0x00, 'C',  'H',  'L',  'O',  //
// 	    0x02, 0x00, 0x00, 0x00,			    //
// 	    'V',  'E',  'R',  0x00, 0x04, 0x00, 0x00, 0x00, //
// 	    'M',  'I',  'D',  'S',  0x08, 0x00, 0x00, 0x00, //
// 	    'Q',  '0',  '4',  '3',  0x64, 0x00, 0x00, 0x00};
//
// 	tag_info tags[2] = {make_raw_tag("VER", "Q043", 4),
// 			    make_uint32_tag("MIDS", 100)};
//
// 	int write_count = write_chlo_stream_frame(buffer, 100, tags, 2);
//
// 	TEST_ASSERT_EQUAL(36, write_count);
// 	TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, buffer, write_count);
// }

void test_random_connection_id(void)
{
	srand(1);
	uint64_t connection_id = random_connection_id();

	// It should have the high-order bits being SCAN when
	TEST_ASSERT_EQUAL(0x5343414e, be64toh(connection_id) >> 32);

	// It should not return the same value for 2 different calls.
	TEST_ASSERT_NOT_EQUAL(connection_id, random_connection_id());

	// Different SRAND seeds should return different values.
	srand(1); // Resetting the seed to 1
	TEST_ASSERT_EQUAL(connection_id, random_connection_id());
	srand(2); // Resetting the seed to 2
	TEST_ASSERT_NOT_EQUAL(connection_id, random_connection_id());
}

int main(void)
{
	UNITY_BEGIN();
	RUN_TEST(test_make_uint32_tag);
	RUN_TEST(test_make_raw_tags_no_data);
	RUN_TEST(test_make_raw_tag);
	RUN_TEST(test_make_pad_tag);
	RUN_TEST(test_pack_tags);
	RUN_TEST(test_random_connection_id);
	// RUN_TEST(test_write_chlo_stream_frame);
	return UNITY_END();
}
