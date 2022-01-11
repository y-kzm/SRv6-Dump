#ifndef SEG6_H
#include <stdint.h>
#include <linux/types.h>
#include <linux/in6.h>	

#define IPPROTO_SRH 43

struct ipv6_sr_hdr {
    uint8_t	    nexthdr;
	uint8_t	    hdrlen;
	uint8_t	    type;
	uint8_t	    segments_left;
	uint8_t	    first_segment; /* Represents the last_entry field of SRH */
	uint8_t	    flags;
	uint16_t	tag;

	struct in6_addr segments[0];
} __attribute__((__packed__));


#endif