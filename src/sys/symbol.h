#ifndef SYS__KERNEL_H
#define SYS__KERNEL_H

void *sym_lookup(const char* sym_name);
int sym_lookup_name(unsigned long symbol, char **res_buf, size_t *res_buflen);

#endif