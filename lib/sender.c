#include "sender.h"

#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <semaphore.h>
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
#include <fcntl.h>
#include <arpa/inet.h>

/*
 * Reads from a file into memory (mmap).
 * Returns the file size in bytes on success or a negative code on error.
 * Caller must munmap the returned pointer.
 */
int64_t read_map(const char *filename, const uint8_t** data, int *fd){
    *fd = open(filename, O_RDONLY);
    if (*fd == -1) return -EIO;
    
    struct stat st;
    if (fstat(*fd, &st) == -1) {
        close(*fd);
        *fd = -1;
        return -EIO;
    }
    uint64_t file_size = st.st_size;
    if (file_size == 0) {
        close(*fd);
        *fd = -1;
        return -EIO;
    }
    void *map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, *fd, 0);
    if (map == MAP_FAILED) {
        close(*fd);
        *fd = -1;
        return -EIO;
    }
    *data = map;
    posix_fadvise(*fd, 0, file_size, POSIX_FADV_SEQUENTIAL);
    madvise((void *)*data, file_size, MADV_SEQUENTIAL);
    return (int64_t)file_size;
}

// Wrapper function for pthreads threading.
void* start_thread(void *args) {
    thread_args opts = *(thread_args *)args;
    switch (opts.task){
        case WRAPPER:
            {
                ssize_t *file_size = malloc(sizeof(ssize_t));
                *file_size = send_file(opts.dest_ip, opts.file);
                return file_size;
            }
        case SENDER:
            {
                int *ret = malloc(sizeof(int));
                *ret = payload_tunnel(opts.socket, opts.queue, opts.window, opts.dest_ip);
                return ret;
            }
        case LISTENER:
            {
                int *ret = malloc(sizeof(int));
                *ret = listen_for_reply(opts.socket, opts.window);
                return ret;
            }
        case RESENDER:
            {
               resend_timeout(opts.window, opts.socket);
               return NULL;
            }
        default:
            return NULL;
    }
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

// Receive a reply and update the retransmit window when an ACK is found.
int listen_for_reply(int socket, sliding_window *window) {
    while (state != ABORT && state != DATA_RECVD) {
        uint8_t buffer[1024];
        
        ssize_t bytes_received = receive_packet(socket, buffer, sizeof(buffer));
        if (bytes_received < 0) {
            return bytes_received;
        }
        if (bytes_received == 0) continue; // Poll timeout, no data

        pthread_mutex_lock(&window->lock);
        int is_valid = validate_reply(buffer, bytes_received, window->queue, window->tail, window->count);

        if (is_valid < 0) {
            pthread_mutex_unlock(&window->lock);
            continue; // Ignored or corrupted packet, do nothing.
        }
        window->queue[is_valid].acknowledged = true;
        pthread_mutex_unlock(&window->lock);
        
        // Slide the window to advance and make room for new packets.
        slide_window(window);
        pthread_cond_signal(&window->ack);

        if (state == DATA_SENT && window->count == 0) state = DATA_RECVD;
    }

    return 0;
}

// Resend any queued packets that exceed the TIMEOUT threshold.
void resend_timeout(sliding_window *window, int socket) {
    while (state != ABORT && state != DATA_RECVD){
        struct timespec soonest_timeout;
        struct timespec current_time;
        clock_gettime(CLOCK_MONOTONIC, &current_time);
        soonest_timeout = current_time;
        soonest_timeout.tv_sec += TIMEOUT;
        bool packet_resent = false;
        pthread_mutex_lock(&window->lock);
        for (int i = 0; i < window->count; i++) {
            int idx = (window->tail + i) % WINDOW_SIZE;
            if (window->queue[idx].in_use && !window->queue[idx].acknowledged) {
                if (current_time.tv_sec > window->queue[idx].timeout_time.tv_sec) {
                    pthread_mutex_unlock(&window->lock);
                    send_packet(socket, window->queue[idx].packet.dest_ip, &window->queue[idx].packet, window->queue[idx].packet_size, window, true, false);
                    pthread_mutex_lock(&window->lock);
                    packet_resent = true;
                    break; // Window could have changed because of dropped lock
                }
                else if (window->queue[idx].timeout_time.tv_sec < soonest_timeout.tv_sec || (window->queue[idx].timeout_time.tv_sec == soonest_timeout.tv_sec && window->queue[idx].timeout_time.tv_nsec < soonest_timeout.tv_nsec)) soonest_timeout = window->queue[idx].timeout_time;
            }
        }
        if (packet_resent) {
            pthread_mutex_unlock(&window->lock);
            continue;
        }
        pthread_cond_timedwait(&window->ack, &window->lock, &soonest_timeout);
        pthread_mutex_unlock(&window->lock);
    }
    if (state == DATA_RECVD) {
        state = FINISHED;
    }
}

int payload_tunnel(int socket, data_queue *queue, sliding_window *window, const char *dest_ip) {
    while (state != ABORT && state != DATA_SENT) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 1;
        if (sem_timedwait(&window->counter, &ts) != 0) continue;
        pthread_mutex_lock(&queue->lock);
        while (state != ABORT && queue->count == 0) {
            struct timespec ts2;
            clock_gettime(CLOCK_REALTIME, &ts2);
            ts2.tv_sec += 1;
            pthread_cond_timedwait(&queue->data_available, &queue->lock, &ts2);
        }
        uint8_t payload[PAYLOAD_SIZE];
        size_t bytes_to_copy = queue->count < PAYLOAD_SIZE ? queue->count : PAYLOAD_SIZE;
        size_t first_chunk = min(bytes_to_copy, queue->capacity - queue->tail);
        memcpy(payload, &queue->buffer[queue->tail], first_chunk);
        if (first_chunk < bytes_to_copy) {
            memcpy(payload + first_chunk, queue->buffer, bytes_to_copy - first_chunk);
        }
        if (bytes_to_copy < PAYLOAD_SIZE) {
            memset(payload + bytes_to_copy, 0, PAYLOAD_SIZE - bytes_to_copy);
        }
        queue->count -= bytes_to_copy;
        queue->tail = (queue->tail + bytes_to_copy) % queue->capacity;
        pthread_mutex_unlock(&queue->lock);
        pthread_cond_signal(&queue->space_available);
        size_t packet_size = 0;
        icmp_packet *packet = generate_custom_ping_packet(getpid() & 0xFFFF, window->next_sequence, 64, payload, PAYLOAD_SIZE, &packet_size);
        while (state != ABORT && send_packet(socket, dest_ip, packet, packet_size, window, false, false) <= 0);
        free(packet);

        if (state == DATA_QUEUED && queue->count == 0) {
            state = DATA_SENT;
            pthread_mutex_lock(&window->lock);
            if (window->count == 0) {
                state = DATA_RECVD;
            }
            pthread_mutex_unlock(&window->lock);
        }
    }
    return 0;
}

ssize_t send_file(const char *dest_ip, const char *in_file) {
    const uint8_t *data = NULL;
    int map_fd = -1;
    ssize_t file_size = read_map(in_file, &data, &map_fd);
    if (file_size < 0) return file_size;
    size_t current = 0;

    uint8_t header[10];
    header[0] = (MAGIC_NUMBER >> 8) & 0xFF;
    header[1] = MAGIC_NUMBER & 0xFF;
    for (int i = 2; i < 10; i++) {
        header[i] = (file_size >> (8 * (9 - i))) & 0xFF;
    }
    
    sliding_window window = {
        .next_sequence = 1
    };
    pthread_mutex_init(&window.lock, NULL);
    sem_init(&window.counter, 0, 5);
    pthread_condattr_t cattr;
    pthread_condattr_init(&cattr);
    pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
    pthread_cond_init(&window.ack, &cattr);
    pthread_condattr_destroy(&cattr);

    uint8_t queued_data[1024] = {0};

    data_queue queue = {
        .buffer = queued_data,
        .capacity = 1024,
        .count = 0,
        .head = 0,
        .tail = 0
    };
    pthread_mutex_init(&queue.lock, NULL);
    pthread_cond_init(&queue.data_available, NULL);
    pthread_cond_init(&queue.space_available, NULL);

    int socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socketfd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    pthread_t resend_thread;
    thread_args *resend_args = malloc(sizeof(thread_args));
    if (resend_args == NULL) {
        state = ABORT;
        return -ENOMEM;
    }
    resend_args->window = &window;
    resend_args->socket = socketfd;
    resend_args->task = RESENDER;
    if (pthread_create(&resend_thread, NULL, start_thread, resend_args) != 0) {
        state = ABORT;
        return -EAGAIN;
    }

    pthread_t listen_thread;
    thread_args *listen_args = malloc(sizeof(thread_args));
    if (listen_args == NULL) {
        state = ABORT;
        return -ENOMEM;
    }
    listen_args->socket = socketfd;
    listen_args->window = &window;
    listen_args->task = LISTENER;
    if (pthread_create(&listen_thread, NULL, start_thread, listen_args) != 0) {
        state = ABORT;
        return -EAGAIN;
    }

    pthread_t sender_thread;
    thread_args *sender_args = malloc(sizeof(thread_args));
    if (sender_args == NULL) {
        state = ABORT;
        return -ENOMEM;
    }
    sender_args->queue = &queue;
    sender_args->window = &window;
    sender_args->dest_ip = dest_ip;
    sender_args->socket = socketfd;
    sender_args->task = SENDER;
    if (pthread_create(&sender_thread, NULL, start_thread, sender_args) != 0) {
        state = ABORT;
        return -EAGAIN;
    }

    // Send header
    sem_wait(&window.counter);
    size_t packet_size = 0;
    icmp_packet *packet = generate_custom_ping_packet(getpid() & 0xFFFF, window.next_sequence, 64, header, 10, &packet_size);
    int send_result = send_packet(socketfd, dest_ip, packet, packet_size, &window, false, false);
    if (send_result < 0) {
        fprintf(stderr, "Failed to send header packet (error code: %d)\n", send_result);
        sem_post(&window.counter);
    }
    free(packet);

    // Wait until the header is acknowledged before queuing any data.
    pthread_mutex_lock(&window.lock);
    while (state != ABORT && window.count > 0) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        ts.tv_sec += 1;
        pthread_cond_timedwait(&window.ack, &window.lock, &ts);
    }
    pthread_mutex_unlock(&window.lock);

    size_t to_copy = min(1024, (size_t)file_size - current);
    size_t first_chunk = min(to_copy, queue.capacity - queue.head);
    pthread_mutex_lock(&queue.lock);
    memcpy(&queue.buffer[queue.head], &data[current], first_chunk);
    if (first_chunk < to_copy)
        memcpy(queue.buffer, &data[current + first_chunk], to_copy - first_chunk);
    queue.head = (queue.head + to_copy) % queue.capacity;
    queue.count += to_copy;
    pthread_mutex_unlock(&queue.lock);
    current += to_copy;

    while (state != ABORT && current < file_size) {
        pthread_mutex_lock(&queue.lock);
        while (state != ABORT && queue.count > queue.capacity - PRODUCE_THRESHOLD) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 1;
            pthread_cond_timedwait(&queue.space_available, &queue.lock, &ts);
        }
        size_t free_space = queue.capacity - queue.count;
        size_t to_copy = min(free_space, (size_t)file_size - current);
        size_t first_chunk = min(to_copy, queue.capacity - queue.head);
        memcpy(&queue.buffer[queue.head], &data[current], first_chunk);
        if (first_chunk < to_copy)
            memcpy(queue.buffer, &data[current + first_chunk], to_copy - first_chunk);
        queue.head = (queue.head + to_copy) % queue.capacity;
        queue.count += to_copy;
        current += to_copy;
        pthread_cond_signal(&queue.data_available);
        pthread_mutex_unlock(&queue.lock);
    }
    state = DATA_QUEUED;
    pthread_cond_signal(&queue.data_available);

    int *sender_ret;
    pthread_join(sender_thread, (void**)&sender_ret);
    if (*sender_ret != 0) fprintf(stderr, "Sender error.");
    free(sender_ret);

    int *listener_ret;
    pthread_join(listen_thread, (void**)&listener_ret);
    if (*listener_ret != 0) fprintf(stderr, "Listener error.");
    free(listener_ret);

    pthread_join(resend_thread, NULL);

    free(sender_args);
    free(listen_args);
    free(resend_args);

    munmap((void*)data, file_size);
    close(map_fd);
    pthread_mutex_destroy(&queue.lock);
    pthread_mutex_destroy(&window.lock);
    pthread_cond_destroy(&queue.data_available);
    pthread_cond_destroy(&queue.space_available);
    pthread_cond_destroy(&window.ack);
    sem_destroy(&window.counter);
    close(socketfd);
    return file_size;
}
