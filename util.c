#include "util.h"
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

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

icmp_packet* generate_payload_tunnel_packet(uint16_t id, uint16_t sequence, const char *payload, size_t *packet_size) {
    size_t payload_len = strlen(payload);
    size_t total_size = sizeof(struct icmphdr) + payload_len;

    icmp_packet *packet = malloc(total_size);
    if (packet == NULL) {
        fprintf(stderr, "Failed to allocate memory.");
        return ENOMEM;
    }

    memset(packet, 0, total_size);

    packet->icmp_header.type = ICMP_ECHO;
    packet->icmp_header.code = 0;
    packet->icmp_header.un.echo.id = htons(id);
    packet->icmp_header.un.echo.sequence = htons(sequence);
    memcpy(packet->payload, payload, payload_len);

    packet->icmp_header.checksum = 0;
    packet->icmp_header.checksum = calculate_checksum(&packet->icmp_header, total_size);
    *packet_size = total_size;
    return packet;
}

int send_packet(int socket, const uint8_t *packet, size_t packet_size, const char *dest_ip, uint8_t ttl) {
    struct sockaddr_in dest_addr;

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;

    if (inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid destination IP address.");
        return -EINVAL;
    }
    
    if (ttl > 0) {
        if (setsockopt(socket, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
            fprintf(stderr, "Failed to set ttl value.");
            return -EINVAL;
        }
    }

    ssize_t bytes_sent = sendto(socket, packet, packet_size, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));

    if (bytes_sent < 0) {
        fprintf(stderr, "Failed to send packet.");
        return -EIO;
    }

    if ((size_t)bytes_sent != packet_size) {
        fprintf(stderr, "Partial send.");
        return -EIO;
    }

    return bytes_sent;
}
