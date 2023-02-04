# What is sGPUpt?
sGPUpt is an automated setup script for new and experienced VFIO users looking to quickly deploy a virtual machine for gaming.

Check below to ensure that the script supports your hardware and distro!

# Functionality
* Checks if your system has valid IOMMU groups
* Installs all packages necessary for desktop virtualization
* Compiles spoofed QEMU (with spice support) & EDK2 OVMF
* Creates VFIO hooks + the required hooks for single GPU passthrough
* Creates a VM based on your system specs with additional features and optimizations

# Usage
```
curl -O https://raw.githubusercontent.com/lexi-src/sGPUpt/master/sGPUpt.sh
chmod +x sGPUpt.sh
sudo ./sGPUpt.sh
```

# Supported Distros
| Distro            | Status |
| ----------------- | ------ |
| Arch Linux        |   ✔️   |
| Manjaro           |   ✔️   |
| Garuda            |   ✔️   |
| Fedora (36,37)    |   ✔️   |
| Nobara (37)       |   ✔️   |
| AlmaLinux (9.1)   |   ✔️   |
| Debian (any)      |   ❌   |
| Ubuntu (22.04+)   |   ✔️   |
| Kubuntu (22.04+)  |   ✔️   |
| Pop!_OS (22.04)   |   ✔️   |
| Linux Mint (21.1) |   ✔️   |

# Supported Hardware
|   CPU + GPU     |  Status | Additional Information                                           |
| --------------- | ------- | ---------------------------------------------------------------- |
| AMD + Nvidia    |    ✔️   | -                                                                |
| AMD + AMD       |    ✔️   | may require [vendor-reset](https://github.com/gnif/vendor-reset) |
| AMD + Intel     |    ❌   | -                                                                |
| Intel + Nvidia  |    ✔️   | -                                                                |
| Intel + AMD     |    ✔️   | may require [vendor-reset](https://github.com/gnif/vendor-reset) |
| Intel + Intel   |    ❌   | -                                                                |

# Want to contribute but can't code?
If you're willing to provide system information related to your cpu, motherboard, iommu groups and other script issues you may be experiencing then please open an issue or chat me on reddit.

# Direct Contacts
Reddit: [lexi-src](https://www.reddit.com/user/lexi-src)
