#ifndef UTIL_H
#define UTIL_H
#include <arpa/inet.h>
#include <stddef.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include <sys/time.h>

#define PAYLOAD_SIZE 56
#define WINDOW_SIZE 5
#define TIMEOUT 5

// Represents an ICMP echo packet with payload and metadata.
typedef struct {
    struct icmphdr icmp_header;
    uint8_t payload[PAYLOAD_SIZE];
    uint8_t ttl;
    const char* dest_ip;
} icmp_packet;

// Tracks a sent packet's state for retransmission and acknowledgement.
typedef struct {
    icmp_packet packet;
    struct timeval timeout_time;
    size_t packet_size;
    bool in_use;
    bool acknowledged;
} tracked_packet;

// Sliding window for managing in-flight packets and sequencing.
typedef struct {
    tracked_packet queue[WINDOW_SIZE];
    uint8_t head;
    uint8_t tail;
    uint8_t count;
    uint64_t next_sequence;
    pthread_mutex_t lock;
    sem_t counter;
} sliding_window;

// Queue for data to be sent by the sender
typedef struct {
    uint8_t *buffer;
    size_t capacity;
    size_t head;
    size_t tail;
    size_t count;
    pthread_mutex_t lock;
} data_queue;

icmp_packet* generate_custom_ping_packet(uint16_t id, uint16_t sequence, uint8_t ttl, const uint8_t *payload, size_t payload_len, size_t *packet_size);
int send_packet(int socket, const char *dest_ip, icmp_packet *packet, size_t packet_size, sliding_window *window, bool resend);
int listen_for_reply(int socket, sliding_window *window);
void resend_timeout(sliding_window *window, int socket);

#endif
