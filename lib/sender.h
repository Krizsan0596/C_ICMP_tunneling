#ifndef SENDER_H
#define SENDER_H

#include "util.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

extern volatile _Atomic program_state state;

int64_t read_map(const char *filename, const uint8_t **data, int *fd);
void* start_thread(void *args);
void slide_window(sliding_window *window);
int validate_reply(uint8_t *buffer, size_t buffer_len, tracked_packet *queue, uint8_t tail, uint8_t count);
int listen_for_reply(int socket, sliding_window *window);
void resend_timeout(sliding_window *window, int socket);
int payload_tunnel(int socket, data_queue *queue, sliding_window *window, const char *dest_ip);
ssize_t send_file(const char *dest_ip, const char *in_file);

#endif
