/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "socket.h"

#include <errno.h>
#include <string.h>

#include "../lib/includes.h"
#include "../lib/logger.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/bpf.h>

#include "state.h"



sock_t get_socket(UNUSED uint32_t id)
{
	char file[32];
	int bpf;
	// Assume failure
	sock_t ret;
	ret.sock = -1;

	// Try to find a valid bpf
	for (int i = 0; i < 128; i++) {
		snprintf(file, sizeof(file), "/dev/bpf%d", i);
		bpf = open(file, O_WRONLY);
		if (bpf != -1 || errno != EBUSY)
			break;
	}

	// Make sure it worked
	if (bpf < 0) {
		return ret;
	}

	// Set up an ifreq to bind to
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, zconf.iface, sizeof(ifr.ifr_name));

	// Bind the bpf to the interface
	if (ioctl(bpf, BIOCSETIF, (char *) &ifr) < 0) {
		return ret;
	}

	// Enable writing the address in
	int write_addr_enable = 1;
	if (ioctl(bpf, BIOCSHDRCMPLT, &write_addr_enable) < 0) {
		return ret;
	}
	ret.sock = bpf;
	return ret;
}


sock_t get_ip_socket(uint32_t id)
{
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock <= 0) {
		log_fatal("send", "couldn't create IP socket. "
			"Are you root? Error: %s\n", strerror(errno));
	}
	const int on = 1;
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on))) {
	    perror("setsockopt");
	    exit(1);
	}

	sock_t s;
	s.sock = sock;
	return s;
}
