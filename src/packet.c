#include <linux/types.h>
#include <linux/string.h>

#include "packet.h"
#include "mem.h"

/**
 * Destructs the packet. Called when packet refcount == 0
 */
void packet_destructor(struct kref *ref)
{
    packet_t *packet = container_of(ref, packet_t, refcount);

    pr_err("[*] destructing packet...");

    // destruct content if it exists
    if (packet->content)
        kzfree(packet->content, packet->content_len);

    kzfree(packet, sizeof(*packet));
}

/**
 * on success: ptr
 * on failure: 0
 */
packet_t *packet_init(const struct raw_packet *buffer, size_t count)
{
    packet_t *packet;
    size_t packet_header_len;

    // do size check
    packet_header_len = sizeof(packet->password) + sizeof(packet->command);
    if (count < packet_header_len || count - packet_header_len > CONTENT_MAX_LEN)
        return ERR_PTR(-EMSGSIZE);

    // allocate memory
    packet = kcalloc(sizeof(*packet), 1, GFP_KERNEL);
    //packet = kcalloc(sizeof(*packet), 1, GFP_KERNEL);
    if (!packet)
        return ERR_PTR(-ENOMEM);
    
    // set fields manually to allow for internal structure packet reorganisation
    memcpy(packet->password, buffer->password, sizeof(packet->password));
    packet->command = buffer->command;
    packet->content_len = count - packet_header_len + 1;

    // create content if necessary, doing +1 for extra nullbyte
    if (packet->content_len - 1 > 0)
    {
        packet->content = kcalloc(packet->content_len, 1, GFP_KERNEL);  // +1 for str
        if (!packet->content)
        {
            kzfree(packet, sizeof(*packet));
            packet = NULL;

            return ERR_PTR(-ENOMEM);
        }

        memcpy(packet->content, &buffer->content, packet->content_len-1);
    }

    kref_init(&packet->refcount);

    return packet;
};