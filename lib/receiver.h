#ifndef RECEIVER_H
#define RECEIVER_H

#include "util.h"
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <netinet/in.h>

int64_t write_map(const char *filename, uint8_t **data, uint64_t file_size, int *fd);
int set_kernel_replies(bool setting);
ssize_t receive_payload(int socket, icmp_packet *ack, uint8_t *data, uint16_t *sequence, struct in_addr *source);
ssize_t receive_file(int socket, char *out_file);

#endif
