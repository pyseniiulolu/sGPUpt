# sGPUpt Intro
sGPUpt is designed for desktop VFIO users looking to passthrough their only GPU.

Check below to ensure compatibility with your hardware and distribution.

# Functionality
* Validates IOMMU groups
* Installs required virtualization packages 
* Compiles spoofed QEMU & EDK2 OVMF
* Creates hooks for single GPU passthrough
* Creates a VM based on your system specs with additional features and optimizations

# Usage
```
curl -O https://raw.githubusercontent.com/lexi-src/sGPUpt/master/sGPUpt.sh
chmod +x sGPUpt.sh
sudo ./sGPUpt.sh
```

# Distro Support
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

# Hardware Support
|   CPU + GPU     |  Status | Additional Information                                           |
| --------------- | ------- | ---------------------------------------------------------------- |
| AMD + Nvidia    |    ✔️   | -                                                                |
| AMD + AMD       |    ✔️   | may require [vendor-reset](https://github.com/gnif/vendor-reset) |
| AMD + Intel     |    ❌   | -                                                                |
| Intel + Nvidia  |    ✔️   | -                                                                |
| Intel + AMD     |    ✔️   | may require [vendor-reset](https://github.com/gnif/vendor-reset) |
| Intel + Intel   |    ❌   | -                                                                |

# Troubleshooting

### [Device is not isolated]
The script found an extra device in one of your IOMMU groups, using a kernel with an ACS patch should resolve the issue.

* Debian-based fix - Install [XanMod](https://xanmod.org/) kernel then add **pcie_acs_override=downstream,multifunction** to grub.
* Arch-based fix - Refer to [Arch Wiki](https://wiki.archlinux.org/title/PCI_passthrough_via_OVMF#Bypassing_the_IOMMU_groups_(ACS_override_patch)).
### [Black screen/BIOS screen]
Known reasons this can occur:
* The hooks are failing due to the GPU driver not releasing the card (possible side effect of CSM being enabled in your BIOS).
* Your card may require a VBIOS, instructions can be found on [Arch Wiki](https://wiki.archlinux.org/title/PCI_passthrough_via_OVMF#UEFI_(OVMF)_compatibility_in_VBIOS).
### [VM instability]
Known Fixes:
* Disable ReBAR in your BIOS.
* Disable CSM in your BIOS.
* Disable svm/vmx in the generated VM configuration.

Still experiencing instability?
* VirtIO drivers can conflict with NVIDIA/AMD drivers so attempt to run your VM without VirtIO devices attached.
* If you're using an existing Windows install from an HDD/SSD you should probably reinstall Windows.

# How to contribute without coding knowledge
Providing detailed information about your cpu, motherboard, iommu groups and other script related issues will improve the script.

If you're willing to provide this information then please open an issue or reach out to me directly.

# Direct Contacts
Reddit: [lexi-src](https://www.reddit.com/user/lexi-src)
