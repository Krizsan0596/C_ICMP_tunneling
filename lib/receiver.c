#include "receiver.h"
#include "sender.h"
#include "util.h"
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

/*
 * Memory maps a file for writing.
 * Returns the file size on success or negative error codes on failure.
 * Caller must munmap the returned pointer.
 */
int64_t write_map(const char *filename, uint8_t **data, uint64_t file_size, int *fd){
    *fd = open(filename, O_RDWR | O_CREAT, 0644);
    if (*fd == -1) return -EIO;
    
    if (ftruncate(*fd, file_size) == -1) {
        close(*fd);
        *fd = -1;
        return -EIO;
    }

    void *map = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, *fd, 0);
    if (map == MAP_FAILED) {
        close(*fd);
        *fd = -1;
        return -EIO;
    }
    *data = map;
    posix_fadvise(*fd, 0, file_size, POSIX_FADV_SEQUENTIAL);
    madvise(*data, file_size, MADV_SEQUENTIAL);
    return (int64_t)file_size;
}

int acknowledge_packet(int socket, icmp_packet *packet) {
    send_packet(socket, packet->dest_ip, packet, sizeof(*packet), NULL, false, true);    
    return 0;
}

ssize_t receive_payload(int socket, icmp_packet *ack, uint8_t *data, uint16_t *sequence, struct in_addr *source) {
    uint8_t buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    ssize_t buffer_size = receive_packet(socket, buffer, sizeof(buffer));

    if (buffer_size <= 0) return buffer_size;
    if (buffer_size < sizeof(struct icmphdr) + sizeof(struct iphdr)) return -2; // Packet too small, broken packet

    struct iphdr *ip_header = (struct iphdr *)buffer;
    int ip_header_len = ip_header->ihl * 4;
    if (ip_header_len >= buffer_size) return -2; // Header too big, broken packet

    struct in_addr src_addr;
    src_addr.s_addr = ip_header->saddr;
    uint8_t *packet = buffer + ip_header_len;
    if (calculate_checksum((unsigned short *)packet, buffer_size - ip_header_len) != 0) return -2; // Incorrect checksum, broken data
    source->s_addr = src_addr.s_addr;

    memcpy(&ack->icmp_header, packet, sizeof(struct icmphdr) + PAYLOAD_SIZE);
    ack->ttl = 64;
    inet_ntop(AF_INET, &src_addr.s_addr, ack->dest_ip, INET_ADDRSTRLEN);

    if (source->s_addr != 0 && memcmp(source, &src_addr, sizeof(struct in_addr)) != 0) { // Not a packet from known tunnel source. 
        acknowledge_packet(socket, ack);  // Normal ICMP Echo Reply for non tunneled packets.
        return -1;
    }
    *sequence = ntohs(((struct icmphdr*) packet)->un.echo.sequence);
    uint8_t *payload = packet + sizeof(struct icmphdr);
    size_t payload_len = buffer_size - (ip_header_len + sizeof(struct icmphdr));
    if (payload_len != PAYLOAD_SIZE) { // Not packet from tunnel
        acknowledge_packet(socket, ack);
        return -1;
    }
    memcpy(data, payload, payload_len);
    return payload_len;
}

ssize_t receive_file(int socket, char *out_file) {
    struct in_addr source = {0};
    bool source_locked = false;
    uint8_t *data = NULL;
    uint64_t received_len = 0;
    uint64_t file_size = 0;
    uint64_t num_chunks;
    bool *recvd_sequences = NULL;
    int map_fd = -1;
    while (!source_locked || received_len < file_size) {
        uint8_t buffer[1024];
        uint16_t sequence;
        icmp_packet ack;
        ssize_t data_len = receive_payload(socket, &ack, buffer, &sequence, &source);
        if (data_len <= 0) continue;
        if (!source_locked) {
            uint8_t magic[2] = { (MAGIC_NUMBER >> 8) & 0xFF, MAGIC_NUMBER & 0xFF };
            if (memcmp(magic, buffer, 2) != 0) {
                memset(&source, 0, sizeof(struct in_addr));
                continue;
            }
            for (int i = 2; i < 10; i++) {
                file_size = (file_size << 8) | buffer[i];
            }
            if (file_size > 65536 * PAYLOAD_SIZE) return -ENOSPC; // 16 bit seq -> 2^16 * PAYLOAD_SIZE (56) is max file size. 
                                                                  // TODO: seq wrapping.
            if(write_map(out_file, &data, file_size, &map_fd) <= 0) return -1;
            num_chunks = ((file_size + PAYLOAD_SIZE - 1)/ PAYLOAD_SIZE);
            recvd_sequences = calloc(num_chunks, sizeof(bool));
            if (recvd_sequences == NULL) return -ENOMEM;
            source_locked = true;
            acknowledge_packet(socket, &ack);
            continue;
        }
        if (sequence < 2) continue; // retransmitted header, ACK was dropped, avoids integer underflow.
        sequence -= 2; // Sequence starts at 1, first packet is header. First data packet is sequence 2.
        if (sequence >= num_chunks) continue; // Received more data than the file size, corrupted sequence, prevent overindexing.
        if (recvd_sequences[sequence]) continue;
        memcpy(&data[sequence * PAYLOAD_SIZE], buffer, min(data_len, (file_size - sequence * PAYLOAD_SIZE))); // data_len includes padding
        recvd_sequences[sequence] = true;
        received_len += min(data_len, (file_size - (uint64_t)sequence * PAYLOAD_SIZE));
        acknowledge_packet(socket, &ack);
    }
    free(recvd_sequences);
    msync(data, file_size, MS_SYNC);
    munmap(data, file_size);
    fsync(map_fd);
    close(map_fd);
    return file_size;
}
