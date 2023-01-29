# [sGPUpt] - single GPU passthrough simplified
sGPUpt is an automated setup script for new and experienced VFIO users looking to setup virtual machines for gaming.

Check below to ensure that the script supports your hardware and distro!

# Functionality
* Installs all packages necessary for desktop virtualization
* Compiles QEMU & EDK2
* Queries your system for optimal VM configuration
* Creates VFIO hooks + the required hooks for your VM
* Creates a VM based on the earlier query then adds CPU pinning + other spoofing features

# Usage
NVIDIA GPUs:
```
curl -O https://raw.githubusercontent.com/lexi-src/sGPUpt/master/sGPUpt.sh
chmod +x sGPUpt.sh
sudo ./sGPUpt.sh "Windows-Gaming" NVIDIA
```

AMD GPUs:
```
curl -O https://raw.githubusercontent.com/lexi-src/sGPUpt/master/sGPUpt.sh
chmod +x sGPUpt.sh
sudo ./sGPUpt.sh "Windows-Gaming" AMD
```

# Supported Distros
| Distro            | Status |
| ----------------- | ------ |
| Arch Linux        |   ✔️   |
| Manjaro           |   ✔️   |
| Garuda            |   ✔️   |
| Fedora (36,37)    |   ✔️   |
| Debian            |   ❌   |
| Ubuntu (22.04+)   |   ✔️   |
| Kubuntu (22.04+)  |   ✔️   |
| Pop!_OS (22.04)   |   ✔️   |
| Linux Mint (21.1) |   ✔️   |
| AlmaLinux (9.1)   |   ✔️   |

# Unsupported Hardware
| Hardware             | Status |
| -------------------- | ------ |
| Intel Arc GPUs       |   ❌   |

I don't have access to this hardware so if you want support for the hardware listed above please PM me on reddit or open an issue.

# Want to contribute but can't code?
Information is key. If you're willing to provide system information such as cpu topology, motherboard info, iommu groups and other script issues you may be experiencing then please DM me on reddit

# Direct Contacts
Reddit: [lexi-src](https://www.reddit.com/user/lexi-src)
