# Netkit

TODO:
- Implement AES-256-CBC decryption
- Replace password hash check loop with memcmp
- Implement PCR allocate command
- Implement ko hotswap
- Implement recipes
- Implement TLS layer
- Netfilter hook
- Find bypass for -EKEYREJECTED on secure boot when loading kmod
- Fix exit cmd (free_module does not free the pages to prevent crash)
- Find out why kallsyms f->f_op->read_iter is not required from userland
