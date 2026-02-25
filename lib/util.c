#include "util.h"
#include <errno.h>
#include <stdio.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>

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
