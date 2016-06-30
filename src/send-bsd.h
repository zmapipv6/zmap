/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef ZMAP_SEND_BSD_H
#define ZMAP_SEND_BSD_H

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if_dl.h>

#include "../lib/includes.h"

#include <netinet/in.h>
#include <net/bpf.h>


#ifdef ZMAP_SEND_LINUX_H
#error "Don't include both send-bsd.h and send-linux.h"
#endif


static struct sockaddr *sa;
//static struct sockaddr_ll *sockaddr;

int send_run_init(UNUSED sock_t sock)
{
	// Don't need to do anything on BSD-like variants
	return EXIT_SUCCESS;
}

int send_packet(sock_t sock, void *buf, int len, UNUSED uint32_t idx)
{
	return write(sock.sock, buf, len);
}

int send_run_ip_init(UNUSED sock_t sock)
{
	struct ifaddrs *ifap,*ifa;
    getifaddrs(&ifap);
    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (!strcmp(ifa->ifa_name, zconf.iface)) {
			sa = ifa->ifa_addr;
			break;
		}
    }
	if (!sa) {
		log_fatal("send", "unable to find specified interfae");
	}
	return EXIT_SUCCESS;
    //freeifaddrs(ifap);
}

int send_ip_packet(sock_t sock, void *buf, int len, UNUSED uint32_t idx)
{
	return sendto(sock.sock, buf, len, 0, sa, sizeof(struct sockaddr));
}

#endif /* ZMAP_SEND_BSD_H */
