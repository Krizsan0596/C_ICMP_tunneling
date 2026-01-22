#ifndef UTIL_H
#define UTIL_H
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define PAYLOAD_SIZE 64
#define WINDOW_SIZE 5
#define TIMEOUT 5

typedef struct {
    struct icmphdr icmp_header;
    uint8_t payload[56];
    uint8_t ttl;
} icmp_packet;

unsigned short calculate_checksum(unsigned short *data, int len);
icmp_packet* generate_custom_ping_packet(uint16_t id, uint16_t sequence, uint8_t ttl, const char *payload, size_t *packet_size);
int validate_reply(char *buffer, size_t buffer_len, icmp_packet *queue);

#endif
