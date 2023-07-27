#ifndef CORE__CMD__HANDLERS_H
#define CORE__CMD__HANDLERS_H

#include "../packet/packet.h"

int cmd_handle_file_read(const struct packet_req *packet, u8 **res_buf, size_t *res_buflen);
int cmd_handle_file_write(const struct packet_req *packet, u8 **res_buf, size_t *res_buflen);
int cmd_handle_file_exec(const struct packet_req *packet, u8 **res_buf, size_t *res_buflen);
int cmd_handle_proxy(const struct packet_req *packet, u8 **res_buf, size_t *res_buflen);
int cmd_handle_exit(const struct packet_req *packet, u8 **res_buf, size_t *res_buflen);

#endif