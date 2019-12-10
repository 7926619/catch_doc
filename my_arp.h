#ifndef MY_ARP_H
#define MY_ARP_H

#include <stdint.h>

#define MAC_LEN     6
#define IP_LEN      4

struct my_arp_hdr {
    uint16_t ar_hrd;                         /* format of hardware address */
    uint16_t ar_pro;                         /* format of protocol address */
    uint8_t  ar_hln;                         /* length of hardware address */
    uint8_t  ar_pln;                         /* length of protocol addres */
    uint16_t ar_op;                          /* operation type */

    uint8_t ar_sha[MAC_LEN];                 /* sender hardware address */
    uint8_t ar_spa[IP_LEN];                  /* sender protocol address */
    uint8_t ar_tha[MAC_LEN];                 /* target hardware address */
    uint8_t ar_tpa[IP_LEN];                  /* target protocol address */
};

#endif // MY_ARP_H
