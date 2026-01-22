#ifndef UTIL_H
#define UTIL_H
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define PAYLOAD_SIZE 64

typedef struct {
    struct iphdr ip_header;
    struct icmphdr icmp_header;
    uint8_t payload[];
} icmp_packet;

unsigned short calculate_checksum(unsigned short *data, int len);
icmp_packet* generate_custom_ping_packet(uint16_t id, uint16_t sequence, uint8_t ttl, const char *payload);

#endif
