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

## Usage
To run the rootkit, optionally tweak it in the configurations, build it using `make` and ship it using `insmod`, or any other kernel module loader.

**==== Please make sure to adjust `CONFIG_NETKIT_DEBUG` to your liking ====**

When `CONFIG_NETKIT_DEBUG` is enabled, the rootkit can only be stopped using the self destruct / exit cmd, and not using rmmod.

```bash
git clone https://github.com/notselwyn/netkit/
cd netkit
make

ls -la netkit.ko
```

### Testing it with notselwyn/kernel-scripts

Since the rootkit was developed with the author's (kernel-scripts)[https://github.com/notselwyn/kernel-scripts], it's a breeze to debug and test. Simply download the scripts and compile a compatible Linux kernel.

To run the kernel:
```bash
cd netkit
create-image.sh
run.sh $KERNEL_PROJ_ROOT
```

To run the rootkit (make sure it's in debug mode to allow for `rmmod` in `run_kmod.sh`):
```bash
cd netkit
run_kmod.sh netkit.ko netkit
run_python.sh client/shell.py
```

### TODO
- Make plans for how Netkit can be used, and if there will be a toolsuite
- Implement segments for rapid IO
- Implement PCR allocate command
- Implement ko hotswap
- Implement recipes
- Implement TLS layer
- Netfilter hook
- Find bypass for -EKEYREJECTED on secure boot when loading kmod
- Fix exit cmd (free_module does not free the pages to prevent crash)
- Fix exec cmd stderr (doesn't want to execute with 2>&1)
- Find out why kallsyms f->f_op->read_iter is not required from userland
