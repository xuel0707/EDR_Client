#include "../include/common.h"

struct dnshdr {
        unsigned short id;
        unsigned short flags;
        unsigned short qdcount;
        unsigned short ancount;
        unsigned short nscount;
        unsigned short arcount;
};

struct dnsquery {
        char *qname;
        char qtype[2];
        char qclass[2];
};

struct resolv_header {
        int id;
        int qr, opcode, aa, tc, rd, ra, rcode;
        int qdcount;
        int ancount;
        int nscount;
        int arcount;
};

struct resolv_answer {
        char dotted[256];
        int atype;
        int aclass;
        int ttl;
        int rdlength;
        unsigned char *rdata;
        int rdoffset;
};

#if 0
extern void decode_header(unsigned char *data, struct resolv_header *h);
extern void extract_dns_request(struct dnsquery *dns_query, char *request);
extern int check_dns_answer(char *dns_hdr, int udp_len,
                        struct sniper_ip *srcip, unsigned short sport,
                        struct sniper_ip *dstip, unsigned short dport);
#endif
