#ifndef CORE__IFACE_H
#define CORE__IFACE_H

int core_process(const u8 *req_buf, size_t req_buflen, u8 **res_buf, size_t *res_buflen);

#endif