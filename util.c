#include "util.h"
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdbool.h>

unsigned short calculate_checksum(unsigned short *data, int len) {
    unsigned long sum = 0;
    unsigned short odd_byte;

    while (len > 1) {
        sum += *data++;
        len -= 2;
    }

    if (len == 1) {
        odd_byte = 0;
        *((unsigned char*)&odd_byte) = *(unsigned char*)data;
        sum += odd_byte;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
}

// Fill a payload buffer with a timestamp followed by an incremental pattern. (Default payload on Linux.)
int construct_default_payload(uint8_t *buf, int len) {
    if (len < sizeof(struct timeval)) return 1;
    for (int i = 0; i < len; i++) {
        buf[i] = (uint8_t)i;
    }

    struct timeval tv;
    gettimeofday(&tv, NULL);
    memcpy(buf, &tv, sizeof(tv));

    return 0;
}

// Build an ICMP echo request packet with a fixed-size payload.
icmp_packet* generate_custom_ping_packet(uint16_t id, uint16_t sequence, uint8_t ttl, const uint8_t *payload, size_t payload_len, size_t *packet_size) {
    if (payload == NULL) {
        fprintf(stderr, "generate_custom_ping_packet: payload argument must not be NULL.\n");
        return NULL;
    }
    
    if (payload_len > PAYLOAD_SIZE) {
        fprintf(stderr, "generate_custom_ping_packet: payload length exceeds maximum of %d bytes.\n", PAYLOAD_SIZE);
        return NULL;
    }
    
    // Always send full PAYLOAD_SIZE to keep packet sizes uniform.
    size_t total_size = sizeof(struct icmphdr) + PAYLOAD_SIZE;

    icmp_packet *packet = malloc(sizeof(icmp_packet));
    if (packet == NULL) {
        fprintf(stderr, "generate_custom_ping_packet: failed to allocate memory.\n");
        return NULL;
    }

    memset(packet, 0, sizeof(icmp_packet));

    packet->icmp_header.type = ICMP_ECHO;
    packet->icmp_header.code = 0;
    packet->icmp_header.un.echo.id = htons(id);
    packet->icmp_header.un.echo.sequence = htons(sequence);
    memcpy(packet->payload, payload, payload_len);
    if (payload_len < PAYLOAD_SIZE) {
        // Zero-pad remaining bytes.
        memset(packet->payload + payload_len, 0, PAYLOAD_SIZE - payload_len);
    }

    packet->icmp_header.checksum = 0;
    packet->icmp_header.checksum = calculate_checksum((unsigned short *)packet, total_size);
    *packet_size = total_size;

    packet->ttl = ttl;

    return packet;
}

// Send an ICMP packet and track it for retransmit.
int send_packet(int socket, const char *dest_ip, icmp_packet *packet, size_t packet_size, sliding_window *window, bool resend) {
    struct sockaddr_in dest_addr;
    icmp_packet *default_packet = NULL;
    size_t default_packet_size = 0;

    if (packet == NULL) {
        uint8_t default_payload[PAYLOAD_SIZE];
        if (construct_default_payload(default_payload, PAYLOAD_SIZE) != 0) return -EINVAL;
        
        default_packet = generate_custom_ping_packet(getpid() & 0xFFFF, 1, 64, default_payload, PAYLOAD_SIZE, &default_packet_size);
        if (default_packet == NULL) {
            return -ENOMEM;
        }
        packet = default_packet;
        packet_size = default_packet_size;
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    // Keep dest_ip with the packet so we can resend later.
    packet->dest_ip = dest_ip;

    if (inet_pton(AF_INET, packet->dest_ip, &dest_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid destination IP address.\n");
        if (default_packet) free(default_packet);
        return -EINVAL;
    }
    
    if (packet->ttl > 0) {
        if (setsockopt(socket, IPPROTO_IP, IP_TTL, &packet->ttl, sizeof(packet->ttl)) < 0) {
            fprintf(stderr, "Failed to set ttl value.\n");
            if (default_packet) free(default_packet);
            return -EINVAL;
        }
    }

    // We send packet_size bytes (header + payload), so the rest of the packet struct is ignored.
    ssize_t bytes_sent = sendto(socket, packet, packet_size, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));

    if (bytes_sent < 0) {
        fprintf(stderr, "Failed to send packet.\n");
        if (default_packet) free(default_packet);
        return -EIO;
    }

    if ((size_t)bytes_sent != packet_size) {
        fprintf(stderr, "Partial send.\n");
        if (default_packet) free(default_packet);
        return -EIO;
    }
    // When resending, packet is already tracked, so do not track again, just reset it's timestamp.
    if (!resend) {
        if (window->queue[window->end].in_use) {
            fprintf(stderr, "Window is full. Cannot track new packet.\n");
            if (default_packet) free(default_packet);
            return -EBUSY;
        }
        pthread_mutex_lock(&window->lock);
        tracked_packet tracked;
        tracked.packet = *packet;
        tracked.packet_size = packet_size;
        tracked.in_use = true;
        tracked.acknowledged = false;
        gettimeofday(&tracked.send_time, NULL);
        window->queue[window->end] = tracked;
        if (window->end < WINDOW_SIZE - 1) window->end++;
        pthread_mutex_unlock(&window->lock);
    }
    else {
        for (int i = 0; i < WINDOW_SIZE; i++) {
            if (memcmp(&window->queue[i].packet, packet, sizeof(icmp_packet)) == 0) {
                pthread_mutex_lock(&window->lock);
                gettimeofday(&window->queue[i].send_time, NULL); 
                pthread_mutex_unlock(&window->lock);
                break;
            }
        }
    }

    if (default_packet) free(default_packet);
    return bytes_sent;
}


// Slides window when first packed is ACKed.
void slide_window(sliding_window *window) {
    if (window->queue[0].acknowledged == false) return;
    int n = WINDOW_SIZE;
    for (int i = 0; i < WINDOW_SIZE; i++) {
        if (window->queue[i].acknowledged == false) {
            n = i;
            break;
        }
    }

    pthread_mutex_lock(&window->lock);
    if (n > 0 && n < WINDOW_SIZE) {
        memmove(window->queue, window->queue + n, (WINDOW_SIZE - n) * sizeof(tracked_packet));
    }

    for (int i = WINDOW_SIZE - n; i < WINDOW_SIZE; i++) {
        window->queue[i].in_use = false;
    }

    window->end -= n;
    pthread_mutex_unlock(&window->lock);
    for (int i = 0; i < n; ++i) sem_post(&window->counter);
}

// Validate an incoming packet and match it to a tracked echo request.
int validate_reply(char *buffer, size_t buffer_len, tracked_packet *queue) {
    struct ip *ip_header = (struct ip*)buffer;
    int ip_header_len = ip_header->ip_hl * 4;

    if (buffer_len < ip_header_len + sizeof(struct icmp)) {
        return -EIO;
    }

    icmp_packet *packet = (icmp_packet*)(buffer + ip_header_len);
    size_t icmp_len = buffer_len - ip_header_len;
    if (calculate_checksum((unsigned short*)packet, icmp_len) != 0) {
        return -1; //Invalid checksum, corrupted packet
    }

    if (packet->icmp_header.type == ICMP_ECHOREPLY) {
        uint16_t sequence = ntohs(packet->icmp_header.un.echo.sequence);
        uint16_t id = ntohs(packet->icmp_header.un.echo.id);
        uint8_t *payload = packet->payload;

        for (int i = 0; i < WINDOW_SIZE; i++) {
            icmp_packet *current = &queue[i].packet;
            uint16_t current_id = ntohs(current->icmp_header.un.echo.id);
            uint16_t current_seq = ntohs(current->icmp_header.un.echo.sequence);
            // Match on id/sequence and full payload to avoid false ACKs.
            if (current_id == id && current_seq == sequence && memcmp(current->payload, payload, PAYLOAD_SIZE) == 0) {
                return i; // ACK for packet at index i
            }
        }
        return -2; // Echo reply to non-tunneled packet, ignore
    }
    else return -3; // Not an echo reply, ignore
}

// Receive a reply and update the retransmit window when an ACK is found.
int listen_for_reply(int socket, sliding_window *window) {
    char buffer[1024];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    
    ssize_t bytes_received = recvfrom(socket, buffer, 1024, 0, (struct sockaddr*)&src_addr, &addr_len);
    if (bytes_received < 0) {
        fprintf(stderr, "Receiving failed.\n");
        return -EIO;
    }

    int is_valid = validate_reply(buffer, bytes_received, window->queue);

    if (is_valid < 0) return -1; // Ignored or corrupted packet, do nothing.
    
    pthread_mutex_lock(&window->lock);
    window->queue[is_valid].acknowledged = true;
    pthread_mutex_unlock(&window->lock);
    
    return 0;
}

// Resend any queued packets that exceed the TIMEOUT threshold.
void resend_timeout(sliding_window *window, int socket) {
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    pthread_mutex_lock(&window->lock);
    for (int i = 0; i < WINDOW_SIZE; i++) {
        if (window->queue[i].in_use && !window->queue[i].acknowledged &&
            current_time.tv_sec > window->queue[i].send_time.tv_sec + TIMEOUT) {
            send_packet(socket, window->queue[i].packet.dest_ip, &window->queue[i].packet, window->queue[i].packet_size, window, true);
        }
    }
    pthread_mutex_unlock(&window->lock);
}
