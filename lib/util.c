#include "util.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>

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

ssize_t receive_packet(int socket, uint8_t *buffer, size_t buffer_size) {
    struct pollfd pfd = { .fd = socket, .events = POLLIN };
    int ret = poll(&pfd, 1, 100); // 100ms timeout
    if (ret < 0) {
        if (errno == EINTR) return 0;
        fprintf(stderr, "poll failed.\n");
        return -EIO;
    }
    if (ret == 0) return 0; // Timeout, no data available

    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    ssize_t bytes_received = recvfrom(socket, buffer, buffer_size, 0, (struct sockaddr*)&src_addr, &addr_len);
    if (bytes_received < 0) {
        fprintf(stderr, "Receiving failed.\n");
        return -EIO;
    }
    return bytes_received;
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
int64_t send_packet(int socket, const char *dest_ip, icmp_packet *packet, size_t packet_size, sliding_window *window, bool resend, bool ack) {
    struct sockaddr_in dest_addr;
    icmp_packet *default_packet = NULL;
    size_t default_packet_size = 0;

    if (packet == NULL) {
        uint8_t default_payload[PAYLOAD_SIZE];
        if (construct_default_payload(default_payload, PAYLOAD_SIZE) != 0) return -EINVAL;
        
        default_packet = generate_custom_ping_packet(getpid() & 0xFFFF, window->next_sequence, 64, default_payload, PAYLOAD_SIZE, &default_packet_size);
        if (default_packet == NULL) {
            return -ENOMEM;
        }
        packet = default_packet;
        packet_size = default_packet_size;
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    // Keep dest_ip with the packet so we can resend later.
    strncpy(packet->dest_ip, dest_ip, INET_ADDRSTRLEN - 1);
    packet->dest_ip[INET_ADDRSTRLEN - 1] = '\0';

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

    if (!ack) {
        // When resending, packet is already tracked, so do not track again, just reset its timeout timestamp.
        if (!resend) {
            pthread_mutex_lock(&window->lock);
            if (window->count >= WINDOW_SIZE) {
                pthread_mutex_unlock(&window->lock);
                fprintf(stderr, "Window is full. Cannot track new packet.\n");
                if (default_packet) free(default_packet);
                return -EBUSY;
            }
            tracked_packet tracked;
            tracked.packet = *packet;
            tracked.packet_size = packet_size;
            tracked.in_use = true;
            tracked.acknowledged = false;
            clock_gettime(CLOCK_MONOTONIC, &tracked.timeout_time);
            tracked.timeout_time.tv_sec += TIMEOUT;
            window->queue[window->head] = tracked;
            window->head = (window->head + 1) % WINDOW_SIZE;
            window->count++;
            window->next_sequence++;
            pthread_mutex_unlock(&window->lock);
        }
        else {
            pthread_mutex_lock(&window->lock);
            for (int i = 0; i < window->count; i++) {
                int idx = (window->tail + i) % WINDOW_SIZE;
                if (memcmp(&window->queue[idx].packet, packet, sizeof(icmp_packet)) == 0) {
                    struct timespec new_timeout;
                    clock_gettime(CLOCK_MONOTONIC, &new_timeout);
                    new_timeout.tv_sec += TIMEOUT;
                    window->queue[idx].timeout_time = new_timeout;
                    break;
                }
            }
            pthread_mutex_unlock(&window->lock);
        }
    }
    if (default_packet) free(default_packet);
    return bytes_sent;
}
