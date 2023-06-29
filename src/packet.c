#include <linux/types.h>
#include <linux/string.h>

#include "packet.h"

/**
 * Destructs the packet. Called when packet refcount == 0
 */
static int packet_destroy(void *_packet)
{
    packet_t *packet = _packet;

    pr_err("[*] destroying packet... (ref count: %d)\n", packet->ref_count.ref_count);

    memset(&packet->content, '\x00', packet->content_len);
    kfree(packet->content);

    memset(&packet, '\x00', sizeof(*packet));
    kfree(packet);
    packet = NULL;
    
    return 0;
}

/**
 * on success: ptr
 * on failure: 0
 * set fields manually to allow for internal structure packet reorganisation
 */
packet_t *packet_init(const struct raw_packet_header *buffer, size_t count)
{
    packet_t *packet;
    size_t packet_header_len;

    packet_header_len = sizeof(packet->password) + sizeof(packet->command);
    if (count < packet_header_len)
        return ERR_PTR(-EDOM);

    packet = kmalloc(sizeof(packet), GFP_KERNEL);
    if (!packet)
        return ERR_PTR(-ENOMEM);
    
    memcpy(packet->password, buffer->password, sizeof(packet->password));
    packet->command = buffer->command;

    packet->content_len = count - packet_header_len;
    packet->content = kmalloc(packet->content_len, GFP_KERNEL);
    if (!packet->content)
    {
        memset(&packet, '\x00', sizeof(*packet));
        kfree(packet);
        packet = NULL;

        return ERR_PTR(-ENOMEM);
    }

    memcpy(packet->content, &buffer->content, packet->content_len);

    packet->ref_count.destructor = packet_destroy;
    GET_REF(packet);

    return packet;
};