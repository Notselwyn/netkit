#ifndef SYS__KERNEL_H
#define SYS__KERNEL_H

void *get_sys_call_table(void);

typedef unsigned long (*_sym_type__kallsyms_lookup_name)(const char*);

_sym_type__kallsyms_lookup_name get_kallsyms_lookup_name(void);

#endif