#ifndef CORE__PACKET__PACKET_H
#define CORE__PACKET__PACKET_H

#include <linux/types.h>
#include <linux/umh.h>
#include <linux/slab.h>

#define MAX_REQ_PACKET_LEN 4096
#define PASSWORD_LEN 8
#define MAX_REQ_CONTENT_LEN (MAX_REQ_PACKET_LEN - PASSWORD_LEN - 1)

#define MAX_RES_CONTENT_LEN (PACKET_MAX_LEN - 8 - 1)

#define STAT_DOM_CORE (2 << 0)
#define STAT_DOM_AUTH (2 << 1)
#define STAT_DOM_CMD (2 << 2)
#define STAT_DOM_PACKET (2 << 3)

int calc_status(int retv, int dom);

/**
 * this is the actual packet that gets send
 */
struct raw_packet_req
{
    u8 auth_id;
    u8 password[PASSWORD_LEN];
    u8 cmd_id;
    u8 content[MAX_REQ_CONTENT_LEN];
} __packed;

typedef struct packet_req
{
    u8 auth_id;
    u8 password[PASSWORD_LEN];
    u8 cmd_id;
    size_t content_len;
    u8 *content;
} packet_req_t;

struct packet_status
{
    int type;
    u8 domain;
} __packed;

struct raw_packet_res
{
    struct packet_status status;
    u8 content[1];
} __packed;

void packet_destructor(packet_req_t *ref);
packet_req_t *packet_req_init(const struct raw_packet_req *buffer, size_t count);

#endif