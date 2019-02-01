/*
 * Jan Rüth 2018
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 */

/* module to perform gQUIC enumeration */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <endian.h>

#include "../../lib/includes.h"
#include "../../lib/xalloc.h"
#include "../../lib/lockfd.h"
#include "../../lib/pbm.h"
#include "logger.h"
#include "probe_modules.h"
#include "packet.h"
#include "aesrand.h"
#include "state.h"
#include "module_udp.h"
#include "module_quic_chlo.h"

#define MAX_UDP_PAYLOAD_LEN 1472
#define UNUSED __attribute__((unused))

#define BE_INT(a,b,c,d) ((uint32_t)(d) | (uint32_t)(c) << 8 | (uint32_t)(b) << 16 | (uint32_t)(a) << 24)

static inline uint32_t MakeQuicTag(char a, char b, char c, char d)
{
	return (uint32_t)(a) | (uint32_t)(b) << 8 | (uint32_t)(c) << 16 |
	       (uint32_t)(d) << 24;
}

/* Public Flags */
#define PUBLIC_FLAG_HAS_VERS      0x01
#define PUBLIC_FLAG_HAS_RST       0x02
#define PUBLIC_FLAG_8BYTE_CONN_ID 0x0C

typedef struct {
	uint8_t public_flags; // should be 0x01 | 0x0C  during sending and should not contain version on recv.
	uint64_t connection_id; // unique!
	uint32_t quic_version;
	uint8_t seq_num; // must start with 1, increases strictly monotonic by one
	uint8_t fnv1a_hash[12]; // 12 byte fnv1a hash
} __attribute__((__packed__)) quic_common_hdr;

#define QUIC_HDR_LEN_BASE       14
#define QUIC_HDR_LEN_WITH_HASH  26

typedef struct {
	uint8_t public_flags;   // should be 0x01 | 0x0C  will have these set
	uint64_t connection_id; // unique!
	uint32_t versions[];    // 4 byte versions appended
} __attribute__((__packed__)) quic_version_neg;

/* The connection ID of the CHLOs. Literal value SCANNING*/
uint64_t connection_id;


/* STREAM Frame Flags and Type */
#define FRAME_TYPE_STREAM                 0x80
#define FRAME_STREAM_FIN                  0x40
#define FRAME_STREAM_HAS_DATA             0x20
#define FRAME_STREAM_CRYPTO_STREAM        0x01
#define FRAME_STREAM_GET_OFFSET_LEN(x)    ((x & 0x1C) >> 2)
#define FRAME_STREAM_CREATE_OFFSET_LEN(x) ((x & 0x07) << 2)
#define FRAME_STREAM_GET_SID_LEN(x)       ((x & 0x03))
#define FRAME_STREAM_CREATE_SID_LEN(x)    (x & 0x03)

// also memory aligned
#define STREAM_FRAME_LEN 4
typedef struct {
	uint8_t type; //Positions (mask): 0x80 | 0x40 | 0x20 |0x1C | 0x03
	uint8_t stream_id;
	uint16_t data_len; // len of data
} quic_stream_frame_packet;

static const int chlo_preface_size = 8;
static const int chlo_udp_payload_size = 1350;
static const int total_packet_size = sizeof(struct ether_header) +
    sizeof(struct ip) + sizeof(struct udphdr) + chlo_udp_payload_size;

enum tag_values {
  TAG_PAD   = 0x50414400,
  TAG_VER   = 0x56455200,
  TAG_PDMD  = 0x50444d44,
  TAG_SMHL  = 0x534d484c,
  TAG_ICLS  = 0x4943534c,
  TAG_MIDS  = 0x4d494453,
  TAG_SCLS  = 0x53434c53,
  TAG_CFCW  = 0x43464357,
  TAG_SFCW  = 0x53464357
};

enum supported_versions {
  VER_Q039 = 0x51303339,
  VER_Q042 = 0x51303432,
  VER_Q043 = 0x51303433,
};

static char filter_rule[32];
static int num_ports = 0;
uint8_t **checker_bitmap = NULL;

probe_module_t module_quic_chlo;

int chlo_quic_global_initialize(struct state_conf *conf)
{
	num_ports = conf->source_port_last - conf->source_port_first + 1;
  assert(num_ports == 1);

	sprintf(filter_rule, "udp src port %d", conf->target_port);
	module_quic_chlo.pcap_filter = filter_rule;

  assert(total_packet_size <= MAX_PACKET_SIZE);
	module_quic_chlo.pcap_snaplen = total_packet_size;
	module_quic_chlo.packet_length = total_packet_size;

  connection_id = htobe64(0x5343414e4e494e47);

	checker_bitmap = pbm_init();

	return EXIT_SUCCESS;
}

int chlo_quic_global_cleanup(__attribute__((unused)) struct state_conf *zconf,
			     __attribute__((unused)) struct state_send *zsend,
			     __attribute__((unused)) struct state_recv *zrecv)
{
	return EXIT_SUCCESS;
}

// then use this to update the hash
__uint128_t fnv1a_128_inc(__uint128_t hash, const uint8_t *data, size_t len)
{
	__uint128_t FNV_primeHI = 16777216;
	__uint128_t FNV_primeLO = 315;
	__uint128_t FNV_prime = FNV_primeHI << 64 | FNV_primeLO;

	for (size_t i = 0; i < len; i++) {
		hash = hash ^ (__uint128_t)data[i];
		hash = hash * FNV_prime;
	}

	return hash;
}

// start with this
__uint128_t fnv1a_128(const uint8_t *data, size_t len)
{
	__uint128_t hashHI = 7809847782465536322;
	__uint128_t hashLO = 7113472399480571277;
	__uint128_t hash = hashHI << 64 | hashLO;
	return fnv1a_128_inc(hash, data, len);
}

void serializeHash(__uint128_t hash, uint8_t out_hash[12])
{
	// endianess I don't care....
	memcpy(out_hash, &hash, 12);
}



int add_chlo_frames(/*void *buffer, int buffer_len*/) {
	// TODO: Separate into its own function and test
	// int num_tags_excluding_pad = 8;
  // int padding_len = stream_frame_len - (CHLO_PREFACE_SIZE + (num_tags_excluding_pad * 4) + ((num_tags_excluding_pad+1) * 8);

	// tag_info tags[8] = {
  //     make_pad_tag(stream_frame_length - CHLO_PREFACE_SIZE - (8 * 12)),
	//     make_raw_tag("VER", "Q043", 4),
	//     make_raw_tag("PDMD", "X509", 4),
	//     make_uint32_tag("SMHL", 1),
	//     make_uint32_tag("ICSL", 600),
	//     make_uint32_tag("MIDS", 100),
	//     make_uint32_tag("SCLS", 1),
	//     make_raw_tag("CFCW", "\0\0\xf0\0", 4), // Use raw as im not
	//     make_raw_tag("SFCW", "\0\0\x60\0", 4), // sure of their values
	// };
  return 0;
}


int chlo_quic_init_perthread(void *buf, macaddr_t *src, macaddr_t *gw,
			     __attribute__((unused)) port_h_t dst_port,
			     __attribute__((unused)) void **arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header(eth_header, src, gw);

	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + sizeof(struct udphdr)
                       + chlo_udp_payload_size);
	make_ip_header(ip_header, IPPROTO_UDP, len);

	struct udphdr *udp_header = (struct udphdr *)(&ip_header[1]);
	make_udp_header(udp_header, zconf.target_port,
                  sizeof(struct udphdr) + chlo_udp_payload_size);

	char *udp_payload = (char *)(&udp_header[1]);

	// Since nothing currently changes between client hellos, we can just
	// initialize the payload data here.
	quic_common_hdr *common_hdr = (quic_common_hdr *)udp_payload;
	common_hdr->public_flags =
	    PUBLIC_FLAG_HAS_VERS | PUBLIC_FLAG_8BYTE_CONN_ID;
	common_hdr->connection_id = connection_id;
	common_hdr->quic_version = htobe32(VER_Q043);
	common_hdr->seq_num = 1;
	// Fill the hash later, but don't hash the hash itself
	memset(common_hdr->fnv1a_hash, 0, sizeof(common_hdr->fnv1a_hash));

	static const int stream_frame_len = 1024;
	quic_stream_frame_packet *frame =
	    (quic_stream_frame_packet *)(udp_payload + QUIC_HDR_LEN_WITH_HASH);
	frame->type = FRAME_TYPE_STREAM | FRAME_STREAM_HAS_DATA |
		      FRAME_STREAM_CREATE_SID_LEN(0);
	frame->stream_id = FRAME_STREAM_CRYPTO_STREAM;
	frame->data_len = htobe16(stream_frame_len);

  // TODO: Add the tags

	// hash the public header
	__uint128_t hash = 0;
	hash = fnv1a_128((uint8_t *)udp_payload, QUIC_HDR_LEN_BASE);
	// hash the payload frames, excluding the hash field itself
	hash = fnv1a_128_inc(hash, (uint8_t *)udp_payload + QUIC_HDR_LEN_WITH_HASH,
                       chlo_udp_payload_size - QUIC_HDR_LEN_WITH_HASH);

	uint8_t serializedHash[12];
	serializeHash(hash, serializedHash);

	memcpy(common_hdr->fnv1a_hash, serializedHash, sizeof(serializedHash));

	return EXIT_SUCCESS;
}

int chlo_quic_make_packet(void *buf, UNUSED size_t *buf_len, ipaddr_n_t src_ip,
			  ipaddr_n_t dst_ip, uint32_t *validation,
			  int probe_num, UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip *ip_header = (struct ip *)(&eth_header[1]);
	struct udphdr *udp_header = (struct udphdr *)&ip_header[1];
	//struct = (struct udphdr*) (&ip_header[1]);

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	udp_header->uh_sport =
	    htons(get_src_port(num_ports, probe_num, validation));

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

	return EXIT_SUCCESS;
}

void chlo_quic_print_packet(FILE *fp, void *packet)
{
	struct ether_header *ethh = (struct ether_header *)packet;
	struct ip *iph = (struct ip *)&ethh[1];
	struct udphdr *udph = (struct udphdr *)(&iph[1]);
	fprintf(fp, "udp { source: %u | dest: %u | checksum: %u }\n",
		ntohs(udph->uh_sport), ntohs(udph->uh_dport),
		ntohl(udph->uh_sum));
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

void chlo_quic_process_packet(const u_char *packet, UNUSED uint32_t len,
			      fieldset_t *fs, UNUSED uint32_t *validation)
{
	struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
	if (ip_hdr->ip_p == IPPROTO_UDP) {
		struct udphdr *udp =
		    (struct udphdr *)((char *)ip_hdr + ip_hdr->ip_hl * 4);

		// Verify that the UDP length is big enough for the header and at least one byte
		uint16_t data_len = ntohs(udp->uh_ulen);
		if (data_len > sizeof(struct udphdr)) {
      int payload_len = data_len - sizeof(struct udphdr);
			uint8_t *payload = (uint8_t *)&udp[1];

			if (payload_len > QUIC_HDR_LEN_BASE) {
				quic_common_hdr *quic_header = ((quic_common_hdr *)payload);

				if (quic_header->connection_id == connection_id) {
					fs_add_string(fs, "classification", (char *)"quic", 0);
					fs_add_uint64(fs, "success", 1);
				}

				// probably we got back a version packet
				if (payload_len < chlo_udp_payload_size) {
					quic_version_neg *vers = (quic_version_neg *)payload;
					if ((vers->public_flags & PUBLIC_FLAG_HAS_VERS) > 0) {

						// contains version flag
						int num_versions =
						    (data_len - sizeof(struct udphdr) - 8 - 1) / 4;
						if (num_versions > 0) {

							// create a list of the versions
							// 4 bytes each + , + [SPACE] + \0
							char *versions = malloc(
                  num_versions * sizeof( uint32_t) + (num_versions - 1) * 2 + 1);
							int next_ver = 0;

							if (*((uint32_t *)&vers ->versions
								      [0]) ==
							    MakeQuicTag(
								'Q', '0', '3',
								'4')) {
								// someone replied with our own version... probalby UDP echo
								fs_modify_string(
								    fs,
								    "classification",
								    (char
									 *)"udp",
								    0);
								fs_modify_uint64(
								    fs,
								    "success",
								    0);
								free(versions);
								return;
							}
							for (int i = 0;
							     i < num_versions;
							     i++) {
								memcpy(
								    &versions
									[next_ver],
								    &vers->versions
									 [i],
								    sizeof(
									uint32_t));
								next_ver += 4;
								if (i !=
								    num_versions -
									1) {
									versions
									    [next_ver++] =
										',';
									versions
									    [next_ver++] =
										' ';
								}
							}
							versions[next_ver] =
							    '\0';
							fs_add_string(
							    fs, "versions",
							    versions, 1);
							//fs_add_binary(fs, "versions", num_versions * sizeof(uint32_t), vers->versions, 0);
						}
					} else if ((vers->public_flags &
						    PUBLIC_FLAG_HAS_RST) > 0) {
						fs_modify_string(fs, "info",
								 (char *)"RST",
								 0);
					}
				}
			}
		} else {
			fs_add_string(fs, "classification", (char *)"udp", 0);
			fs_add_uint64(fs, "success", 0);
		}
	}
}

int chlo_quic_validate_packet(const struct ip *ip_hdr, uint32_t len,
			      __attribute__((unused)) uint32_t *src_ip,
			      UNUSED uint32_t *validation)
{
	if (ip_hdr->ip_p == IPPROTO_UDP) {
		if ((4 * ip_hdr->ip_hl + sizeof(struct udphdr)) > len) {
			// buffer not large enough to contain expected udp header
			return 0;
		}

		int already_checked =
		    pbm_check(checker_bitmap, ntohl(ip_hdr->ip_src.s_addr));
		if (already_checked) {
			return 0;
		}

		pbm_set(checker_bitmap, ntohl(ip_hdr->ip_src.s_addr));

		return 1;
	}

	return 0;
}

void free_tag_info(tag_info *tag)
{
	assert(tag != NULL);
	if (tag->value_len > 0) {
		tag->value_len = 0;
		free(tag->value);
	}
	tag->value = NULL;
}

tag_info make_raw_tag(const void *type, const void *value, int value_len)
{
	assert(type != NULL);
	assert(value != NULL || value_len == 0);

	tag_info tag;
	strncpy(tag.type, type, 4);

	tag.value_len = value_len;
	if (value_len > 0) {
		tag.value = malloc(value_len);
		memcpy(tag.value, value, value_len);
	}

	return tag;
}

tag_info make_uint32_tag(const void *type, uint32_t value)
{
	uint32_t le_value = htole32(value);
	return make_raw_tag(type, (void *)&le_value, 4);
}

tag_info make_pad_tag(int length)
{
	tag_info tag;

	const char *type = "PAD";
	strncpy(tag.type, type, 4);

	tag.value_len = length;
	if (length > 0) {
		tag.value = malloc(length);
		memset(tag.value, 0x2d, length);
	}

	return tag;
}

int pack_tags(const tag_info *tags, int num_tags, void *buffer, int buffer_len)
{
	int offset = 0;
	uint8_t *next_tag = (uint8_t *)buffer;
	uint8_t *tag_data_start = (uint8_t *)buffer + (num_tags * 8);
	assert(tag_data_start <= (uint8_t *)buffer + buffer_len);
	const uint8_t *buffer_end = (uint8_t *)buffer + buffer_len;

	for (int i = 0; i < num_tags; ++i) {
		assert((tag_data_start + offset + tags[i].value_len) <=
		       buffer_end);

		memcpy(next_tag, tags[i].type, 4);
		*(uint32_t *)(next_tag + 4) =
		    htole32(offset + tags[i].value_len);

		memcpy(tag_data_start + offset, tags[i].value,
		       tags[i].value_len);

		offset += tags[i].value_len;
		next_tag += 8;
	}

	return offset + (num_tags * 8);
}

int write_chlo(void *buffer, int buffer_len, const tag_info *tags, int num_tags)
{
	const int kPrefaceSize = CHLO_PREFACE_SIZE;
	assert(buffer_len >= kPrefaceSize);
	assert(num_tags <= UINT16_MAX);

	uint8_t *data_buffer = (uint8_t *)buffer;

	memcpy(&data_buffer[0], "CHLO", 4);
	*((uint16_t *)&data_buffer[4]) = htole16(num_tags);
	memset(&data_buffer[6], 0, 2); // Padding

	int tags_size = pack_tags(tags, num_tags, data_buffer + kPrefaceSize,
				  buffer_len - kPrefaceSize);
	assert(tags_size <= UINT16_MAX);

	return kPrefaceSize + tags_size;
}

static fielddef_t fields[] = {
    {.name = "classification",
     .type = "string",
     .desc = "packet classification"},
    {.name = "success",
     .type = "int",
     .desc = "is response considered success"},
    {.name = "versions", .type = "string", .desc = "versions if reported"},
    {.name = "info", .type = "string", .desc = "info"}};

probe_module_t module_quic_chlo = {
    .name = "quic_chlo",
    // we are resetting the actual packet length during initialization of the module
    .packet_length = sizeof(struct ether_header) + sizeof(struct ip) +
		     sizeof(struct udphdr) + QUIC_HDR_LEN_WITH_HASH +
		     STREAM_FRAME_LEN + INCHOATE_CHLO_LEN +
		     CLIENTHELLO_MIN_SIZE,
    // this gets replaced by the actual port during global init
    .pcap_filter = "udp",
    // this gets replaced by the actual payload we expect to get back
    .pcap_snaplen = 1500,
    .port_args = 1,
    .thread_initialize = &chlo_quic_init_perthread,
    .global_initialize = &chlo_quic_global_initialize,
    .make_packet = &chlo_quic_make_packet,
    .print_packet = &chlo_quic_print_packet,
    .validate_packet = &chlo_quic_validate_packet,
    .process_packet = &chlo_quic_process_packet,
    .close = &chlo_quic_global_cleanup,
    .helptext = "Probe module that sends QUIC CHLO packets to hosts.",
    .fields = fields,
    .numfields = sizeof(fields) / sizeof(fields[0])};

