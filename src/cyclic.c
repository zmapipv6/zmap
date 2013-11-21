/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

/*
 * cyclic provides an inexpensive approach to iterating over the IPv4 address
 * space in a random(-ish) manner such that we connect to every host once in
 * a scan execution without having to keep track of the IPs that have been
 * scanned or need to be scanned and such that each scan has a different 
 * ordering. We accomplish this by utilizing a cyclic multiplicative group 
 * of integers modulo a prime and generating a new primitive root (generator)
 * for each scan.
 *
 * We know that 3 is a generator of (Z mod 2^32 + 15 - {0}, *) 
 * and that we have coverage over the entire address space because 2**32 + 15
 * is prime and ||(Z mod PRIME - {0}, *)|| == PRIME - 1. Therefore, we
 * just need to find a new generator (primitive root) of the cyclic group for
 * each scan that we perform.
 *
 * Because generators map to generators over an isomorphism, we can efficiently
 * find random primitive roots of our mult. group by finding random generators
 * of the group (Zp-1, +) which is isomorphic to (Zp*, *). Specifically the
 * generators of (Zp-1, +) are { s | (s, p-1) == 1 } which implies that
 * the generators of (Zp*, *) are { d^s | (s, p-1) == 1 }. where d is a known
 * generator of the multiplicative group. We efficiently find
 * generators of the additive group by precalculating the psub1_f of
 * p - 1 and randomly checking random numbers against the psub1_f until
 * we find one that is coprime and map it into Zp*. Because
 * totient(totient(p)) ~= 10^9, this should take relatively few
 * iterations to find a new generator. 
 */

#include "cyclic.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>
#include <string.h>
#include <math.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <gmp.h>

#include "../lib/logger.h"
#include "../lib/blacklist.h"

#include "state.h"
#include "aesrand.h"

#define LSRC "cyclic"

typedef struct cyclic_group {
	uint64_t prime;
	uint64_t known_primroot;
	size_t num_prime_factors;	// number of unique prime factors of (prime-1)
	uint64_t prime_factors[10];	// unique prime factors of (prime-1)
} cyclic_group_t;

struct cyclic {
	uint64_t prime;
	uint64_t primroot;
	uint64_t current;
	uint64_t num_addrs;
	const cyclic_group_t *group;
};

// We will pick the first cyclic group from this list that is
// larger than the number of IPs in our whitelist. E.g. for an
// entire Internet scan, this would be cyclic32
// Note: this list should remain ordered by size (primes) ascending.
static cyclic_group_t groups[] = {
	{ // 2^16 + 1
		.prime = 65537,
		.known_primroot = 3,
		.prime_factors = {2},
		.num_prime_factors = 1
	},
	{ // 2^24 + 43
		.prime = 16777259,
		.known_primroot = 2,
		.prime_factors = {2, 23, 103, 3541},
		.num_prime_factors = 4
	},
	{ // 2^28 + 3
		.prime = 268435459,
		.known_primroot = 2,
		.prime_factors = {2, 3, 19, 87211},
		.num_prime_factors = 4
	},
	{ // 2^32 + 15
		.prime = 4294967311,
		.known_primroot = 3,
		.prime_factors = {2, 3, 5, 131, 364289},
		.num_prime_factors = 5
	}
};


// selected prime/primitive root that we'll use as the generator

#define COPRIME 1
#define NOT_COPRIME 0

// check whether two integers are coprime
static int check_coprime(uint64_t check, const cyclic_group_t *group)
{
	for (unsigned i=0; i < group->num_prime_factors; i++) {
		if (group->prime_factors[i] > check && !(group->prime_factors[i] % check)) {
			return NOT_COPRIME;
		} else if (group->prime_factors[i] < check && !(check % group->prime_factors[i])) {
			return NOT_COPRIME;
		} else if (group->prime_factors[i] == check) {
			return NOT_COPRIME;
		}
	}
	return COPRIME;
}

// find gen of cyclic group Z modulo PRIME
static uint64_t find_primroot(const cyclic_group_t *group)
{
	// what luck, rand() returns a uint32_t!
	uint32_t candidate = (uint32_t) aesrand_getword() & 0xFFFFFFFF;
	while(check_coprime(candidate, group) != COPRIME) {
		++candidate;
	}
	// pre-modded result is gigantic so use GMP
	mpz_t base, power, prime, primroot;
	mpz_init_set_d(base, (double) group->known_primroot);
	mpz_init_set_d(power, (double) candidate);
	mpz_init_set_d(prime, (double) group->prime);
	mpz_init(primroot);
	mpz_powm(primroot, base, power, prime);
	uint64_t retv = (uint64_t) mpz_get_ui(primroot);
	mpz_clear(base);
	mpz_clear(power);
	mpz_clear(prime);
	mpz_clear(primroot);
	return retv;
}

cyclic_t* cyclic_init(uint32_t primroot_, uint32_t current_)
{
	assert(!(!primroot_ && current_));
	// Initialize blacklist
	if (blacklist_init(zconf.whitelist_filename, zconf.blacklist_filename,
			zconf.destination_cidrs, zconf.destination_cidrs_len,
			NULL, 0)) {
		return NULL;
	}
	cyclic_t* c = malloc(sizeof(cyclic_t));
	memset(c, 0, sizeof(cyclic_t));
	c->num_addrs = blacklist_count_allowed();
	if (!c->num_addrs) {
		log_error("blacklist", "no addresses are eligible to be scanned in the "
				"current configuration. This may be because the "
				"blacklist being used by ZMap (%s) prevents "
				"any addresses from receiving probe packets.",
				zconf.blacklist_filename
			);
		exit(EXIT_FAILURE);
	}

	for (uint32_t i=0; i<sizeof(groups)/sizeof(groups[0]); i++) {
		if (groups[i].prime > c->num_addrs) {
			c->group = &groups[i];
			log_debug("cyclic", "using prime %lu, known_primroot %lu",
					c->group->prime, c->group->known_primroot);
			c->prime = groups[i].prime;
			break;
		}
	}

	if (zconf.use_seed) {
		aesrand_init(zconf.seed+1);
	} else {
		aesrand_init(0);
	}
	if (!primroot_) {
		do {
			c->primroot = find_primroot(c->group);
		} while (c->primroot >= (1LL << 32));
		log_debug(LSRC, "primitive root: %lld", c->primroot);
		c->current = (uint32_t) aesrand_getword() & 0xFFFFFFFF;
		log_debug(LSRC, "starting point: %lld", c->current);
	} else {
		c->primroot = primroot_;
		log_debug(LSRC, "primitive root %lld specified by caller",
				c->primroot);
		if (!current_) {
			c->current = (uint32_t) aesrand_getword() & 0xFFFFFFFF;
			log_debug(LSRC, "no cyclic starting point, "
					 "selected random startpoint: %lld",
					 c->current);
		} else {
			c->current = current_;
		    log_debug(LSRC, "starting point %lld specified by caller",
				    c->current);
		}
	}
	zconf.generator = c->primroot;
	// make sure current is an allowed ip
	cyclic_get_next_ip(c);

	return 0;
}

uint32_t cyclic_get_curr_ip(cyclic_t* c)
{
	return (uint32_t) blacklist_lookup_index(c->current - 1);
}

uint32_t cyclic_get_primroot(cyclic_t* c)
{
	return (uint32_t) c->primroot;
}

static inline uint32_t cyclic_get_next_elem(cyclic_t* c)
{
	do {
		c->current *= c->primroot;
		c->current %= c->prime;
	} while (c->current >= (1LL << 32));
	return (uint32_t) c->current;
}

uint32_t cyclic_get_next_ip(cyclic_t* c)
{
	while (1) {
		uint32_t candidate = cyclic_get_next_elem(c);
		if (candidate-1 < c->num_addrs) {
			return blacklist_lookup_index(candidate-1);
		}
		zsend.blacklisted++;
	}
}

void cyclic_free(cyclic_t *c)
{
	free(c);
}

