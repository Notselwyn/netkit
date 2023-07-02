#ifndef PACKET_H
#define PACKET_H

#include <linux/types.h>
#include <linux/umh.h>
#include <linux/slab.h>

#define PACKET_MAX_LEN 4096
#define CONTENT_MAX_LEN 4087
#define PASSWORD_LEN 8

/**
 * this is the actual packet that gets send
 */
struct raw_packet
{
    u8 password[PASSWORD_LEN];
    u8 command;
    u8 content[CONTENT_MAX_LEN];
};

typedef struct packet
{
    struct kref refcount;

    u8 password[PASSWORD_LEN];
    u8 command;
    size_t content_len;
    u8 *content;
    
} packet_t;

void packet_destructor(struct kref *ref);
packet_t *packet_init(const struct raw_packet *buffer, size_t count);

#endif