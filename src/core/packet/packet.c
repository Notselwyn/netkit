#include <linux/types.h>
#include <linux/string.h>

#include "packet.h"

#include "../../sys/mem.h"
#include "../../sys/debug.h"

/**
 * Destructs the packet. Called when packet refcount == 0
 */
void packet_destructor(packet_req_t *packet)
{
    NETKIT_LOG("[*] destructing packet...");

    // destruct content if it exists
    if (packet->content)
        kzfree(packet->content, packet->content_len);

    kzfree(packet, sizeof(*packet));
}

/**
 * on success: ptr
 * on failure: 0
 */
packet_req_t *packet_req_init(const struct raw_packet_req *buffer, size_t count)
{
    packet_req_t *packet;
    size_t packet_header_len;

    NETKIT_LOG("[*] doing req size check...\n");

    // do size check
    packet_header_len = sizeof(packet->auth_id) + sizeof(packet->password) + sizeof(packet->cmd_id);
    if (count < packet_header_len || count > MAX_REQ_PACKET_LEN)
        return ERR_PTR(-EMSGSIZE);

    NETKIT_LOG("[*] allocating packet...\n");

    // allocate memory
    packet = kzmalloc(sizeof(*packet), GFP_KERNEL);
    if (!packet)
        return ERR_PTR(-ENOMEM);
    
    // set fields manually to allow for field randomization
    packet->auth_id = buffer->auth_id;
    memcpy(packet->password, buffer->password, sizeof(packet->password));
    packet->cmd_id = buffer->cmd_id;
    packet->content_len = count - packet_header_len;

    if (packet->content_len - 1 == 0)
        return packet;

    // create content if necessary
    packet->content = kzmalloc(packet->content_len, GFP_KERNEL);
    if (!packet->content)
    {
        kzfree(packet, sizeof(*packet));

        return ERR_PTR(-ENOMEM);
    }

    memcpy(packet->content, &buffer->content, packet->content_len);

    return packet;
};