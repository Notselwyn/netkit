# Netkit

### Conventions
- Memory management:
    - If callee allocates **out_param, then caller needs to clean
    - If caller allocates in_param, then caller needs to clean
    - Caller must initialize *out_param to NULL
- Encoding schemes
    - The encoding subsystem acts like a stack.
    - `output = L1_encode(L2_encode(eval_packet(L2_decode(L1_decode(input)))))`.
    - The downside of this and the mem mgnt conventions is that L1_decode_output remains in memory even when at eval_packet(), where it's not necessary.
        - This leads to O(n) space complexity, whilst it could be O(1) space complexity if the callee cleaned for the caller.
        - Preventing this would make the code a mess, so we sarcrifice space complexity for readability (and hence security).

### TODO
- Make plans for how Netkit can be used, and if there will be a toolsuite
- Implement PCR allocate command
- Implement ko hotswap
- Implement recipes
- Implement TLS layer
- Netfilter hook
- Find bypass for -EKEYREJECTED on secure boot when loading kmod
- Fix exit cmd (free_module does not free the pages to prevent crash)
- Find out why kallsyms f->f_op->read_iter is not required from userland
