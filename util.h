#ifndef UTIL_H
#define UTIL_H
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/time.h>

#define PAYLOAD_SIZE 56
#define WINDOW_SIZE 5
#define TIMEOUT 5

typedef struct {
    struct icmphdr icmp_header;
    uint8_t payload[PAYLOAD_SIZE];
    uint8_t ttl;
    const char* dest_ip;
} icmp_packet;

typedef struct {
    icmp_packet packet;
    struct timeval send_time;
    size_t packet_size;
    bool in_use;
    bool acknowledged;
} tracked_packet;

typedef struct {
    tracked_packet queue[WINDOW_SIZE];
    uint8_t base;
    uint8_t end;
    uint64_t next_sequence;
} sliding_window;

unsigned short calculate_checksum(unsigned short *data, int len);
icmp_packet* generate_custom_ping_packet(uint16_t id, uint16_t sequence, uint8_t ttl, const uint8_t *payload, size_t payload_len, size_t *packet_size);
int send_packet(int socket, const char *dest_ip, icmp_packet *packet, size_t packet_size, tracked_packet *queue, bool resend);
int listen_for_reply(int socket, tracked_packet *queue);
int validate_reply(char *buffer, size_t buffer_len, tracked_packet *queue);
void resend_timeout(tracked_packet *queue, int socket);

#endif
