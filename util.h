#ifndef UTIL_H
#define UTIL_H
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/time.h>

#define PAYLOAD_SIZE 64
#define WINDOW_SIZE 5
#define TIMEOUT 5

typedef struct {
    struct icmphdr icmp_header;
    uint8_t payload[56];
    uint8_t ttl;
    const char* dest_ip;
} icmp_packet;

typedef struct {
    icmp_packet packet;
    struct timeval send_time;
} tracked_packet;

unsigned short calculate_checksum(unsigned short *data, int len);
icmp_packet* generate_custom_ping_packet(uint16_t id, uint16_t sequence, uint8_t ttl, const char *payload, size_t *packet_size);
int send_packet(int socket, const char *dest_ip, icmp_packet *packet, size_t packet_size, tracked_packet *queue, bool resend);
int listen_for_reply(int socket, tracked_packet *queue);
int validate_reply(char *buffer, size_t buffer_len, tracked_packet *queue);
void resend_timeout(tracked_packet *queue, int socket);

#endif
