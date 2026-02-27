#ifndef UTIL_H
#define UTIL_H
#include <stddef.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <sys/time.h>

#define PAYLOAD_SIZE 56
#define WINDOW_SIZE 5
#define TIMEOUT 5
#define PRODUCE_THRESHOLD 256 // Only load new data into the queue when there are 256 free bytes.
#define MAGIC_NUMBER 0xBEEF // Placeholder, swap for unique.
#define min(a, b) ((a) < (b) ? (a) : (b))

typedef enum {
    RUNNING,
    DATA_QUEUED,
    DATA_SENT,
    DATA_RECVD,
    FINISHED,
    ABORT
} program_state;

// Represents an ICMP echo packet with payload and metadata.
typedef struct {
    struct icmphdr icmp_header;
    uint8_t payload[PAYLOAD_SIZE];
    uint8_t ttl;
    char dest_ip[INET_ADDRSTRLEN];
} icmp_packet;

// Tracks a sent packet's state for retransmission and acknowledgement.
typedef struct {
    icmp_packet packet;
    struct timespec timeout_time;
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
    pthread_cond_t ack;
} sliding_window;

// Queue for data to be sent by the sender
typedef struct {
    uint8_t *buffer;
    size_t capacity;
    size_t head;
    size_t tail;
    size_t count;
    pthread_mutex_t lock;
    pthread_cond_t data_available;
    pthread_cond_t space_available;
} data_queue;

typedef enum {
    SENDER, LISTENER, RESENDER, WRAPPER
} thread_func;

typedef struct {
    thread_func task;
    int socket;
    const char *dest_ip;
    const char *file;
    sliding_window *window;
    data_queue *queue;
} thread_args;

unsigned short calculate_checksum(unsigned short *data, int len);
ssize_t receive_packet(int socket, uint8_t *buffer, size_t buffer_size);
int construct_default_payload(uint8_t *buf, int len);
icmp_packet* generate_custom_ping_packet(uint16_t id, uint16_t sequence, uint8_t ttl, const uint8_t *payload, size_t payload_len, size_t *packet_size);
int64_t send_packet(int socket, const char *dest_ip, icmp_packet *packet, size_t packet_size, sliding_window *window, bool resend, bool ack);

#endif
