#include "util.h"
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
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
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
}

icmp_packet* generate_custom_ping_packet(uint16_t id, uint16_t sequence, uint8_t ttl, const char *payload, size_t *packet_size) {
    size_t payload_len = strlen(payload);
    size_t total_size = sizeof(struct icmphdr) + payload_len;

    icmp_packet *packet = malloc(sizeof(icmp_packet));
    if (packet == NULL) {
        fprintf(stderr, "Failed to allocate memory.");
        return NULL;
    }

    memset(packet, 0, sizeof(icmp_packet));

    packet->icmp_header.type = ICMP_ECHO;
    packet->icmp_header.code = 0;
    packet->icmp_header.un.echo.id = htons(id);
    packet->icmp_header.un.echo.sequence = htons(sequence);
    memcpy(packet->payload, payload, payload_len);

    packet->icmp_header.checksum = 0;
    packet->icmp_header.checksum = calculate_checksum((unsigned short *)&packet->icmp_header, total_size);
    *packet_size = total_size;

    packet->ttl = ttl;

    return packet;
}

int send_packet(int socket, const char *dest_ip, icmp_packet *packet, size_t packet_size, tracked_packet *queue, bool resend) {
    struct sockaddr_in dest_addr;
    icmp_packet *default_packet = NULL;
    size_t default_packet_size = 0;

    if (packet == NULL) {
        char default_payload[56];
        for (int i = 0; i < 56; i++) {
            default_payload[i] = 0x10 + (i % 0x3F);
        }
        default_payload[55] = '\0';
        
        default_packet = generate_custom_ping_packet(getpid() & 0xFFFF, 1, 64, default_payload, &default_packet_size);
        if (default_packet == NULL) {
            return -ENOMEM;
        }
        packet = default_packet;
        packet_size = default_packet_size;
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    packet->dest_ip = dest_ip;

    if (inet_pton(AF_INET, packet->dest_ip, &dest_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid destination IP address.");
        if (default_packet) free(default_packet);
        return -EINVAL;
    }
    
    if (packet->ttl > 0) {
        if (setsockopt(socket, IPPROTO_IP, IP_TTL, &packet->ttl, sizeof(packet->ttl)) < 0) {
            fprintf(stderr, "Failed to set ttl value.");
            if (default_packet) free(default_packet);
            return -EINVAL;
        }
    }

    ssize_t bytes_sent = sendto(socket, packet, packet_size, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));

    if (bytes_sent < 0) {
        fprintf(stderr, "Failed to send packet.");
        if (default_packet) free(default_packet);
        return -EIO;
    }

    if ((size_t)bytes_sent != packet_size) {
        fprintf(stderr, "Partial send.");
        if (default_packet) free(default_packet);
        return -EIO;
    }
    if (!resend) {
        tracked_packet tracked;
        tracked.packet = *packet;
        gettimeofday(&tracked.send_time, NULL);
        queue[WINDOW_SIZE - 1] = tracked;
    }

    return bytes_sent;
}

int listen_for_reply(int socket, tracked_packet *queue) {
    char buffer[1024];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    
    ssize_t bytes_received = recvfrom(socket, buffer, 1024, 0, (struct sockaddr*)&src_addr, &addr_len);
    if (bytes_received < 0) {
        fprintf(stderr, "Receiving failed.");
        return -EIO;
    }

    int is_valid = validate_reply(buffer, bytes_received, queue);

    if (is_valid < 0) return -1; // Ignored or corrupted packet, do nothing.
    free(&queue[is_valid]);
    for (int i = is_valid + 1; i < WINDOW_SIZE; i++) {
        queue[i - 1] = queue[i];
    }
}

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
            if (current->icmp_header.un.echo.id == id && current->icmp_header.un.echo.sequence == sequence && memcmp(current->payload, payload, PAYLOAD_SIZE) == 0) {
                return i; // ACK for packet at index i
            }
        }
        return -2; // Echo reply to non-tunneled packet, ignore
    }
    else return -3; // Not an echo reply, ignore
}

void resend_timeout(tracked_packet *queue, int socket) {
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    for (int i = 0; i < WINDOW_SIZE; i++) {
        if (queue[i].send_time.tv_sec + TIMEOUT < current_time.tv_sec) continue;
        send_packet(socket, queue[i].packet.dest_ip, &queue[i].packet, sizeof(queue[i].packet), queue, true);
    }
}
