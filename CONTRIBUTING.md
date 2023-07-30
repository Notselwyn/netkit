# Contributing
Thank you for considering to contribute to the project. 

## Code conventions
We try to keep the code as secure and clean as possible, and hence we would like to ask you to abide to the following conventions:
- Memory
 management:
    - If callee allocates **out_param, then caller needs to clean
    - If caller allocates in_param, then caller needs to clean
    - Caller must initialize *out_param to NULL
- Encoding schemes
    - The encoding subsystem acts like a stack.
    - `output = L1_encode(L2_encode(eval_packet(L2_decode(L1_decode(input)))))`.
    - The downside of this and the mem mgnt conventions is that L1_decode_output remains in memory even when at eval_packet(), where it's not necessary.
        - This leads to O(n) space complexity, whilst it could be O(1) space complexity if the callee cleaned for the caller.
        - Preventing this would make the code a mess, so we sarcrifice space complexity for readability (and hence security).

## Testing
To test, make sure to properly adapt the config settings.

### Testing scripts

Block incoming iptables (except SSH: 22/tcp)
```bash
iptables -P OUTPUT ACCEPT
iptables -A INPUT -j ACCEPT -i lo
iptables -A INPUT -j ACCEPT -p tcp --dport 22
iptables -A INPUT -j REJECT --reject-with icmp-host-unreachable
```

## TODO
We feel like the following things need to be done:
- Make plans for how Netkit can be used, and if there will be a toolsuite
- Implement netfilter bypass for outgoing conns
- Implement max connections
- Implement segments for rapid IO
- Implement PCR allocate command
- Implement ko hotswap
- Implement recipes
- Implement TLS layer
- Find bypass for -EKEYREJECTED on secure boot when loading hotswap kmod
- Fix exit cmd (free_module does not free the pages to prevent crash)
- Fix exec cmd stderr (doesn't want to execute with 2>&1)
- Fix memory leak 
- Find out why kallsyms f->f_op->read_iter is not required from userland
