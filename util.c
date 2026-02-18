#include "util.h"
#include <bits/time.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <semaphore.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>

/*
 * Reads from a file into memory (mmap).
 * Returns the file size in bytes on success or a negative code on error.
 * Caller must munmap the returned pointer.
 */
int64_t read_map(const char *filename, const uint8_t** data){
    int fd = open(filename, O_RDONLY);
    if (fd == -1) return -EIO;
    
    struct stat st;
    if (fstat(fd, &st) == -1) {
        close(fd);
        return -EIO;
    }
    uint64_t file_size = st.st_size;
    if (file_size == 0) {
        close(fd);
        return -EIO;
    }
    void *map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return -EIO;
    *data = map;
    return (int64_t)file_size;
}

/*
 * Memory maps a file for writing.
 * Returns the file size on success or negative error codes on failure.
 * Caller must munmap the returned pointer.
 */
int64_t write_map(const char *filename, uint8_t **data, uint64_t file_size){
    int fd = open(filename, O_RDWR);
    if (fd == -1) return -EIO;
    
    if (ftruncate(fd, file_size) == -1) {
        close(fd);
        return -EIO;
    }

    void *map = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return -EIO;
    *data = map;
    return (int64_t)file_size;
}

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
int64_t send_packet(int socket, const char *dest_ip, icmp_packet *packet, size_t packet_size, sliding_window *window, bool resend) {
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
        gettimeofday(&tracked.timeout_time, NULL);
        tracked.timeout_time.tv_sec += TIMEOUT;
        window->queue[window->head] = tracked;
        window->head = (window->head + 1) % WINDOW_SIZE;
        window->count++;
        pthread_mutex_unlock(&window->lock);
    }
    else {
    for (int i = 0; i < window->count; i++) {
            int idx = (window->tail + i) % WINDOW_SIZE;
            if (memcmp(&window->queue[idx].packet, packet, sizeof(icmp_packet)) == 0) {
                pthread_mutex_lock(&window->lock);
                gettimeofday(&window->queue[idx].timeout_time, NULL); 
                pthread_mutex_unlock(&window->lock);
                break;
            }
        }
    }

    if (default_packet) free(default_packet);
    return bytes_sent;
}


// Slides window when first packet is ACKed.
void slide_window(sliding_window *window) {
    pthread_mutex_lock(&window->lock);
    if (window->count == 0 || window->queue[window->tail].acknowledged == false) {
        pthread_mutex_unlock(&window->lock);
        return;
    }
    int n = 0;
    while (n < window->count && window->queue[(window->tail + n) % WINDOW_SIZE].acknowledged) {
        window->queue[(window->tail + n) % WINDOW_SIZE].in_use = false;
        n++;
    }

    window->tail = (window->tail + n) % WINDOW_SIZE;
    window->count -= n;
    pthread_mutex_unlock(&window->lock);
    for (int i = 0; i < n; ++i) sem_post(&window->counter);
}

// Validate an incoming packet and match it to a tracked echo request.
int validate_reply(uint8_t *buffer, size_t buffer_len, tracked_packet *queue, uint8_t tail, uint8_t count) {
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

        if (id != (getpid() & 0xFFFF)) {
            return -4; // Echo reply to packet not sent by the program.
        }

        for (int i = 0; i < count; i++) {
            int idx = (tail + i) % WINDOW_SIZE;
            icmp_packet *current = &queue[idx].packet;
            uint16_t current_id = ntohs(current->icmp_header.un.echo.id);
            uint16_t current_seq = ntohs(current->icmp_header.un.echo.sequence);
            // Match on id/sequence and full payload to avoid false ACKs.
            if (current_id == id && current_seq == sequence && memcmp(current->payload, payload, PAYLOAD_SIZE) == 0) {
                return idx; // ACK for packet at index idx
            }
        }
        return -2; // Echo reply to non-tunneled packet, ignore
    }
    else return -3; // Not an echo reply, ignore
}

ssize_t receive_packet(int socket, uint8_t *buffer, size_t buffer_size) {
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    
    ssize_t bytes_received = recvfrom(socket, buffer, buffer_size, 0, (struct sockaddr*)&src_addr, &addr_len);
    if (bytes_received < 0) {
        fprintf(stderr, "Receiving failed.\n");
        return -EIO;
    }
    return bytes_received;
}

// Receive a reply and update the retransmit window when an ACK is found.
int listen_for_reply(int socket, sliding_window *window) {
    uint8_t buffer[1024];
    
    ssize_t bytes_received = receive_packet(socket, buffer, sizeof(buffer));
    if (bytes_received < 0) {
        return bytes_received;
    }

    pthread_mutex_lock(&window->lock);
    int is_valid = validate_reply(buffer, bytes_received, window->queue, window->tail, window->count);

    if (is_valid < 0) return -1; // Ignored or corrupted packet, do nothing.
    
    window->queue[is_valid].acknowledged = true;
    pthread_mutex_unlock(&window->lock);
    
    // Slide the window to advance and make room for new packets.
    slide_window(window);
    
    return 0;
}

// Resend any queued packets that exceed the TIMEOUT threshold.
void resend_timeout(sliding_window *window, int socket) {
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    pthread_mutex_lock(&window->lock);
    for (int i = 0; i < window->count; i++) {
        int idx = (window->tail + i) % WINDOW_SIZE;
        if (window->queue[idx].in_use && !window->queue[idx].acknowledged &&
            current_time.tv_sec > window->queue[idx].timeout_time.tv_sec) {
            pthread_mutex_unlock(&window->lock);
            send_packet(socket, window->queue[idx].packet.dest_ip, &window->queue[idx].packet, window->queue[idx].packet_size, window, true);
            pthread_mutex_lock(&window->lock);
        }
    }
    pthread_mutex_unlock(&window->lock);
}

int payload_tunnel(int socket, data_queue *queue, sliding_window *window, const char *dest_ip) {
    while (true) {
        pthread_mutex_lock(&queue->lock);
        if (queue->count > 0 && sem_trywait(&window->counter) == 0) {
            uint8_t payload[PAYLOAD_SIZE];
            size_t bytes_to_copy = queue->count < PAYLOAD_SIZE ? queue->count : PAYLOAD_SIZE;
            memcpy(payload, &queue->buffer[queue->tail], bytes_to_copy);
            if (bytes_to_copy < PAYLOAD_SIZE) {
                memset(payload + bytes_to_copy, 0, PAYLOAD_SIZE - bytes_to_copy);
            }
            queue->count -= bytes_to_copy;
            queue->tail = (queue->tail + bytes_to_copy) % queue->capacity;
            pthread_mutex_unlock(&queue->lock);
            size_t packet_size = 0;
            icmp_packet *packet = generate_custom_ping_packet(getpid() & 0xFFFF, window->next_sequence, 64, payload, PAYLOAD_SIZE, &packet_size);
            send_packet(socket, dest_ip, packet, packet_size, window, false);
            free(packet);
        } else {
            pthread_mutex_unlock(&queue->lock);
            usleep(500000);
        }
        resend_timeout(window, socket);
    }
}

ssize_t receive_payload(int socket, uint8_t *data, struct in_addr *source) {
    uint8_t buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    size_t buffer_size = receive_packet(socket, buffer, sizeof(buffer));

    struct iphdr *ip_header = (struct iphdr *)buffer;
    int ip_header_len = ip_header->ihl * 4;

    struct in_addr *src_addr;
    src_addr->s_addr = ip_header->saddr;
    if (source->s_addr != 0 && memcmp(source, src_addr, sizeof(struct in_addr)) != 0) return -1; // Not a packet from known tunnel source.
    uint8_t *packet = buffer + ip_header_len;
    if (calculate_checksum((unsigned short *)packet, buffer_size - ip_header_len) != 0) return -2; // Incorrect checksum, broken data
    uint8_t *payload = packet + sizeof(struct icmphdr);
    size_t payload_len = buffer_size - (ip_header_len + sizeof(struct icmphdr));
    if (payload_len != PAYLOAD_SIZE) return -2; // Not packet from tunnel
    memcpy(data, payload, payload_len);
    source->s_addr = src_addr->s_addr;
    return payload_len;
}

ssize_t receive_file(int socket, char *out_file) {
    struct in_addr source = {0};
    bool source_locked = false;
    uint8_t *data = NULL;
    uint8_t *current = NULL;
    uint64_t received_len = 0;
    uint64_t file_size = 0;
    do {
        uint8_t buffer[1024];
        ssize_t data_len = receive_payload(socket, buffer, &source);
        if (data_len < 0) continue;
        if (!source_locked) {
            uint8_t magic[2] = { (MAGIC_NUMBER >> 8) & 0xFF, MAGIC_NUMBER & 0xFF };
            if (memcmp(magic, buffer, 2) != 0) {
                memset(&source, 0, sizeof(struct in_addr));
                continue;
            }
            for (int i = 2; i < 11; i++) {
                file_size = (file_size << 8) | buffer[i]; // Sender has to transmit magic number + file size before the actual file.
            }
            if(write_map(out_file, &data, file_size) <= 0) return -1;
            current = data;
            source_locked = true;
            continue;
        }
        memcpy(current, buffer, min(data_len, (file_size - data_len))); // data_len includes padding
        received_len += min(data_len, (file_size - data_len));
    } while (received_len < file_size);
    munmap(data, file_size);
    return file_size;
}

ssize_t send_file(int socket, const char *dest_ip, char *in_file) {
    const uint8_t *data = NULL;
    ssize_t file_size = read_map(in_file, &data);
    if (file_size < 0) return file_size;
    size_t current = 0;

    uint8_t header[11];
    header[0] = (MAGIC_NUMBER >> 8) & 0xFF;
    header[1] = MAGIC_NUMBER & 0xFF;
    for (int i = 2; i < 11; i++) {
        header[i] = (file_size >> (8 * (10 - i))) & 0xFF;
    }
    
    sliding_window window = {
        .queue = {0},
        .count = 0,
        .head = 0,
        .tail = 0,
        .next_sequence = 1
    };
    pthread_mutex_init(&window.lock, NULL);
    sem_init(&window.counter, 0, 5);

    uint8_t queued_data[1024] = {0};

    data_queue queue = {
        .buffer = queued_data,
        .capacity = WINDOW_SIZE * PAYLOAD_SIZE,
        .count = 0,
        .head = 0,
        .tail = queue.capacity
    };
    pthread_mutex_init(&queue.lock, NULL);

    // Send header
    size_t packet_size = 0;
    icmp_packet *packet = generate_custom_ping_packet(getpid() & 0xFFFF, window.next_sequence, 64, header, 11, &packet_size);
    send_packet(socket, dest_ip, packet, packet_size, &window, false);

    memcpy(&queue.buffer[queue.head], &data[current], min(64, file_size - current));
    current += min(64, file_size - current);
    queue.head += min(64, file_size - current);
    queue.count += min(64, file_size - current);
    payload_tunnel(socket, &queue, &window, dest_ip); // TODO: Loop memcpy and move this to separate thread.
    
    munmap((void*)data, file_size);
    return file_size;
}
