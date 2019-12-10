#ifndef MY_THR_H
#define MY_THR_H

#include <pcap.h>
#include "my_arp.h"

typedef struct _ip_set {
    char *sender_ip;
    char *target_ip;
} ip_set;

struct thr_arg_arp
{
    pcap_t *fp;
    struct my_arp_hdr *arp_hdr_s;
    struct my_arp_hdr *arp_hdr_t;
    ip_set sets;
};

struct thr_arg_icmp
{
    pcap_t *fp;
    struct my_arp_hdr *arp_hdr_s;
    struct my_arp_hdr *arp_hdr_t;
};

#endif // MY_THR_H
