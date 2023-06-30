#include <linux/types.h>
#include <linux/string.h>

#include "packet.h"

/**
 * Destructs the packet. Called when packet refcount == 0
 */
void packet_destructor(struct kref *ref)
{
    packet_t *packet = container_of(ref, packet_t, refcount);

    if (packet->content)
    {
        memset(packet->content, '\x00', packet->content_len);
        kfree(packet->content);
    }

    memset(packet, '\x00', sizeof(*packet));
    kfree(packet);
}

/**
 * on success: ptr
 * on failure: 0
 */
packet_t *packet_init(const struct raw_packet *buffer, size_t count)
{
    packet_t *packet;
    size_t packet_header_len;

    packet_header_len = sizeof(packet->password) + sizeof(packet->command);
    if (count < packet_header_len || count - packet_header_len > CONTENT_MAX_LEN)
        return ERR_PTR(-EMSGSIZE);

    packet = kcalloc(sizeof(packet), 1, GFP_KERNEL);
    if (!packet)
        return ERR_PTR(-ENOMEM);
    
    // set fields manually to allow for internal structure packet reorganisation
    memcpy(packet->password, buffer->password, sizeof(packet->password));
    packet->command = buffer->command;
    packet->content_len = count - packet_header_len;

    if (packet->content_len > 0)
    {
        packet->content = kcalloc(packet->content_len, 1, GFP_KERNEL);
        if (!packet->content)
        {
            memset(&packet, '\x00', sizeof(*packet));
            kfree(packet);
            packet = NULL;

            return ERR_PTR(-ENOMEM);
        }

        memcpy(packet->content, &buffer->content, packet->content_len);
    }

    
    kref_init(&packet->refcount);

    return packet;
};