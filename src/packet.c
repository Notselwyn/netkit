
#include <linux/types.h>

#include "packet.h"

/**
 * on success: ptr
 * on failure: 0
 * set fields manually to allow for internal structure packet reorganisation
 */
packet_t *packet_init(struct raw_packet_header *buffer, size_t count)
{
    packet_t *packet;
    size_t content_size;
    size_t packet_header_len;

    packet_header_len = sizeof(packet->password) + sizeof(packet->command);
    if (count < packet_header_len)
        return ERR_PTR(-EDOM);

    packet = kmalloc(sizeof(packet), GFP_KERNEL);
    if (!packet)
        return ERR_PTR(-ENOMEM);
    
    memcpy(packet->password, buffer->password, sizeof(packet->password));
    packet->command = buffer->command;

    content_size = count - packet_header_len;
    packet->content = kmalloc(content_size, GFP_KERNEL);
    if (!packet->content)
    {
        kfree(packet);
        return ERR_PTR(-ENOMEM);
    }

    memcpy(packet->content, &buffer->content, content_size);

    return packet;
};