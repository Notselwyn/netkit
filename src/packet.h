#ifndef PACKET_H
#define PACKET_H

#include <linux/types.h>
#include <linux/umh.h>
#include <linux/slab.h>

#define PASSWORD_LEN 8
#define GET_REF(var) ({ var->_ref_count += 1; })
#define PUT_REF(var) ({ \
    var->_ref_count -= 1; \
    if (var->_ref_count == 0) \
        kfree(var); \
})

struct raw_packet_header
{
    u8 password[PASSWORD_LEN];
    u8 command;
    u8 content;
};

typedef struct packet
{
    u8 _ref_count;
    u8 password[PASSWORD_LEN];
    u8 command;
    u8 *content;
} packet_t;

packet_t *packet_init(struct raw_packet_header *buffer, size_t count);

#endif