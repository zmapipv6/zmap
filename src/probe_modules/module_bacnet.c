/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "../../lib/includes.h"
#include "packet.h"
#include "probe_modules.h"
#include "module_bacnet.h"
#include "module_udp.h"

#define ICMP_UNREACH_HEADER_SIZE 8

probe_module_t module_bacnet;

static int num_ports;

static uint8_t bacnet_body[] = { 0x0c, 0x02, 0x3f, 0xff, 0xff, 0x19, 0x4b };
#define BACNET_BODY_LEN 7

static inline uint8_t get_invoke_id(uint32_t *validation)
{
	return (uint8_t) ((validation[1] >> 24) & 0xFF);
}

int bacnet_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
                uint32_t *validation, int probe_num, void *arg)
{
        struct ether_header *eth_header = (struct ether_header *) buf;
        struct ip *ip_header = (struct ip*) (&eth_header[1]);
        struct udphdr *udp_header = (struct udphdr*) &ip_header[1];
        struct bacnet_probe *bnp = (struct bacnet_probe*) &udp_header[1];
        uint8_t *body = (uint8_t*) &bnp[1];

        ip_header->ip_src.s_addr = src_ip;
        ip_header->ip_dst.s_addr = dst_ip;
        ip_header->ip_sum = 0;

        udp_header->uh_sport = htons(get_src_port(num_ports, probe_num, validation));

        bnp->vlc.type = ZMAP_BACNET_TYPE_IP;
        bnp->vlc.function = ZMAP_BACNET_FUNCTION_UNICAST_NPDU;
        bnp->vlc.length = htons(0x11);

        bnp->npdu.version = ZMAP_BACNET_NPDU_VERSION_ASHRAE_135_1995;
        bnp->npdu.control = 0x04;

        bnp->apdu.type_flags = 0x00;
        bnp->apdu.max_segments_apdu = 0x05;
        bnp->apdu.invoke_id = get_invoke_id(validation);
        bnp->apdu.server_choice = 0x0c;
        memcpy(body, bacnet_body, BACNET_BODY_LEN);

        ip_header->ip_sum = zmap_ip_checksum((unsigned short *) ip_header);

        return EXIT_SUCCESS;
}

int bacnet_validate_packet(const struct ip *ip_hdr, uint32_t len,
                uint32_t *src_ip, uint32_t *validation)
{
	if (!udp_do_validate_packet(ip_hdr, len, src_ip, validation, num_ports)) {
		return 0;
	}
	struct udphdr *udp;
        if (ip_hdr->ip_p ==  IPPROTO_UDP) {
        	udp = (struct udphdr *) ((char *) ip_hdr + ip_hdr->ip_hl * 4);
        	uint16_t sport = ntohs(udp->uh_sport);
		if (sport != zconf.target_port) {
			return 0;
		}
	}
	if (udp->uh_ulen < sizeof(struct udphdr)) {
		return 0;
	}
	if (udp->uh_ulen < sizeof(struct udphdr) + sizeof(struct bacnet_vlc)) {
		return 0;
	}
	struct bacnet_vlc *vlc = (struct bacnet_vlc *) &udp[1];
	if (vlc->type != ZMAP_BACNET_TYPE_IP) {
		return 0;
	}
	return 1;
}

void bacnet_process_packet(const u_char *packet, uint32_t len, fieldset_t *fs,
        __attribute__((unused)) uint32_t *validation)
{
	uint32_t ip_offset = sizeof(struct ether_header);
        struct ip *ip_hdr = (struct ip*) &packet[ip_offset];

        if (ip_hdr->ip_p == IPPROTO_UDP) {
		uint32_t udp_offset = ip_offset + ip_hdr->ip_hl * 4;
		assert(udp_offset + sizeof(struct udphdr) < len);
                struct udphdr *udp = (struct udphdr*) &packet[udp_offset];
                fs_add_string(fs, "classification", (char*) "ntp", 0);
                fs_add_uint64(fs, "success", 1);
                fs_add_uint64(fs, "sport", ntohs(udp->uh_sport));
                fs_add_uint64(fs, "dport", ntohs(udp->uh_dport));
                fs_add_null(fs, "icmp_responder");
                fs_add_null(fs, "icmp_type");
                fs_add_null(fs, "icmp_code");
                fs_add_null(fs, "icmp_unreach_str");

		uint32_t payload_offset = udp_offset + sizeof(struct udphdr);
		assert(payload_offset < len);
		const uint8_t *payload = &packet[payload_offset];
		uint32_t payload_len = len - payload_offset;
		fs_add_binary(fs, "udp_payload", payload_len, payload, 0);

		#if 0
		// Pull out the BACNet Device ID
		static const uint32_t bacnet_header_len =
				sizeof(struct bacnet_vlc)
				+ sizeof(struct bacnet_npdu)
				+ sizeof(struct bacnet_apdu);
		uint32_t device_id = 1234;
		int bad_bacnet = 0;
		if (payload_len < bacnet_header_len) {
			bad_bacnet = 1;
			goto fail;
		}
		struct bacnet_vlc *vlc = (struct bacnet_vlc*) payload;
		uint32_t npdu_offset = payload_offset
				+ sizeof(struct bacnet_vlc);
		struct bacnet_npdu *npdu = &packet[npdu_offset];
		uint32_t apdu_offset = npdu_offset
				+ sizeof(struct bacnet_npdu);
		struct bacnet_apdu *apdu = &packet[apdu_offset];

		if (vlc->function != ZMAP_BACNET_FUNCTION_UNICAST_NPDU 
				|| ntohs(vlc->length) > payload_len
				|| ntohs(vlc->length) < bacnet_header_len ) {
			bad_bacnet = 1;	
			goto fail;
		}
		if (npdu->version != ZMAP_BACNET_NPDU_VERSION_ASHRAE_135_1995
				|| npdu->control & 0xF8) {
			bad_bacnet = 1;
			goto fail;
		}
		if ((apdu->type_flags & 0x30) != 0x30) {
			bad_bacnet = 1;
			goto fail;
		}
		if (apdu->server_choice
				!= ZMAP_BACNET_SERVER_CHOICE_READ_PROPERTY) {
			bad_bacnet = 1;
			goto fail;
		}
		uint32_t body_len = ntohs(vlc->length) - bacnet_header_len;
		uint32_t body_offset = payload_offset + bacnet_header_len;
		uint8_t *body = &packet[body_offset];
		if (body_len < 2) {
			bad_bacnet = 1;
			goto fail;
		}
		uint8_t context_tag = body[0];
		if (context_tag != 0x0c) {
			bad_bacnet = 1;
			goto fail;
		}
		#if 0
		uint32_t identifier = *(uint32_t *) &body[1];
		if (identifier != htonl(0x0203f7a1)) {
			bad_bacnet = 1;
			goto fail;
		}
		#endif
		fail:
			if (bad_bacnet) {
				fs_add_null(fs, "device_id");
			} else {
				fs_add_uint64(fs, "device_id", device_id);
			}
		#endif
	} else if (ip_hdr->ip_p ==  IPPROTO_ICMP) {
		struct icmp *icmp = (struct icmp *) ((char *) ip_hdr + ip_hdr -> ip_hl * 4);
		struct ip *ip_inner = (struct ip *) ((char*) icmp + ICMP_UNREACH_HEADER_SIZE);

		fs_modify_string(fs, "saddr", make_ip_str(ip_inner->ip_dst.s_addr), 1);
		fs_add_string(fs, "classification", (char*) "icmp-unreach", 0);
		fs_add_uint64(fs, "success", 0);
		fs_add_null(fs, "sport");
		fs_add_null(fs, "dport");
		fs_add_string(fs, "icmp_responder", make_ip_str(ip_hdr->ip_src.s_addr), 1);
		fs_add_uint64(fs, "icmp_type", icmp->icmp_type);
		fs_add_uint64(fs, "icmp_code", icmp->icmp_code);
		fs_add_null(fs, "icmp_unreach_str");
		fs_add_null(fs, "udp_payload");
	} else {
		fs_add_string(fs, "classification", (char *) "other", 0);
		fs_add_uint64(fs, "success", 0);
		fs_add_null(fs, "sport");
		fs_add_null(fs, "dport");
		fs_add_null(fs, "icmp_responder");
		fs_add_null(fs, "icmp_type");
		fs_add_null(fs, "icmp_code");
		fs_add_null(fs, "icmp_unreach_str");
		fs_add_null(fs, "udp_payload");
	}
}

int bacnet_global_initialize(struct state_conf *conf) {
	num_ports = conf->source_port_last - conf->source_port_first + 1;
	return EXIT_SUCCESS;
}

int bacnet_init_perthread(void *buf, macaddr_t *src,
		macaddr_t *gw, __attribute__((unused)) port_h_t dst_port,
		void **arg)
{
        memset(buf, 0, MAX_PACKET_SIZE);
        struct ether_header *eth_header = (struct ether_header *) buf;
        struct ip *ip_header = (struct ip*)(&eth_header[1]);
        struct udphdr *udp_header = (struct udphdr*)(&ip_header[1]);
        make_eth_header(eth_header, src, gw);

        uint16_t ip_len = sizeof(struct ip) + sizeof(struct udphdr) + 0x11;
        assert(ip_len <= MAX_PACKET_SIZE);
        make_ip_header(ip_header, IPPROTO_UDP, htons(ip_len));

        uint16_t udp_len = sizeof(struct udphdr) + 0x11;
        make_udp_header(udp_header, zconf.target_port, udp_len);

        uint32_t seed = aesrand_getword(zconf.aes);
        aesrand_t *aes = aesrand_init_from_seed(seed);
        *arg = aes;

        return EXIT_SUCCESS;
}

static fielddef_t fields[] = {
        {.name = "classification", .type = "string", .desc = "packet classification"},
        {.name = "success", .type = "int", .desc = "is  response considered success"},
        {.name = "sport", .type = "int", .desc = "UDP source port"},
        {.name = "dport", .type = "int", .desc = "UDP destination port"},
        {.name = "icmp_responder", .type = "string", .desc = "Source IP of ICMP_UNREACH messages"},
        {.name = "icmp_type", .type = "int", .desc = "icmp message type"},
        {.name = "icmp_code", .type = "int", .desc = "icmp message sub type code"},
        {.name = "icmp_unreach_str", .type = "string", .desc = "for icmp_unreach responses, the string version of icmp_code "},
	{.name = "udp_payload", .type = "binary", .desc = "UDP payload"},
	{.name = "device_id", .type = "int", .desc = "BACNet Device ID"},
};

probe_module_t module_bacnet = {
        .name = "bacnet",
        .packet_length = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + 0x11,
        .pcap_filter = "udp || icmp",
        .pcap_snaplen = 1500,
        .port_args = 1,
        .thread_initialize = &bacnet_init_perthread,
        .global_initialize = &bacnet_global_initialize,
        .make_packet = &bacnet_make_packet,
        .print_packet = &udp_print_packet,
        .validate_packet = &bacnet_validate_packet,
        .process_packet = &bacnet_process_packet,
        .close = &udp_global_cleanup,
        .output_type = OUTPUT_TYPE_STATIC,
        .fields = fields,
        .numfields = sizeof(fields)/sizeof(fields[0])
};
