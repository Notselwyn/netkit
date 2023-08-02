# Netkit

Netkit is a purposefully small rootkit which can be used by clients over network to maintain a sneaky foothold into a device.

### Overview
Netkit has several features:
- File read
- File write
- File execute (stderr + stdout)
- Proxy
- Self deletion (stopping the module from running and free'ing resources)

### Usage

Once the rootkit is loaded into the system, a user may want to interact with it using the provided psuedo-shell:
```bash
cd netkit
python3 client/shell.py
```

### Compilation
To run the rootkit, optionally tweak it in the configurations, build it using `make` and ship it using `insmod`, or any other kernel module loader.

**==== Please make sure to adjust `CONFIG_NETKIT_DEBUG` to your liking ====**

If `CONFIG_NETKIT_DEBUG` is enabled, then stealth mode is enabled and the rootkit can only be stopped using the self destruct / exit cmd (not using rmmod).

Make sure to set $KERNEL_DIR to your kernels' hedaer files, like `KERNEL_DIR=/usr/src/linux-headers-$(uname -r)`

```bash
git clone https://github.com/notselwyn/netkit/
cd netkit
make KERNEL_DIR=$KERNEL_DIR

ls -la netkit.ko
```

### Running it with notselwyn/kernel-scripts

Since the rootkit was developed with the author's [kernel-scripts](https://github.com/notselwyn/kernel-scripts), it's a breeze to debug and test. Simply download the scripts and compile a compatible Linux kernel.

To run the kernel:
```bash
cd netkit
create-image.sh
run.sh $KERNEL_DIR
```

To run and interact with the rootkit (make sure it's in debug mode to allow for `rmmod` in `run_kmod.sh`):
```bash
cd netkit
run_kmod.sh netkit.ko netkit
run_python.sh client/shell.py
```
