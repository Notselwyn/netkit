#ifndef PACKET_H
#define PACKET_H

#include <linux/types.h>
#include <linux/umh.h>
#include <linux/slab.h>

#include "types.h"

#define PASSWORD_LEN 8

struct raw_packet_header
{
    u8 password[PASSWORD_LEN];
    u8 command;
    u8 content;
};

typedef struct packet
{
    struct ref_count ref_count;

    u8 password[PASSWORD_LEN];
    u8 command;
    size_t content_len;
    u8 *content;
    
} packet_t;

packet_t *packet_init(const struct raw_packet_header *buffer, size_t count);

#endif