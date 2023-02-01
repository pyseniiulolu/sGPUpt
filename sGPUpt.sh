#!/bin/bash
LANG=en_US.UTF-8

version=0.1.0
author=lexi-src
tool=sGPUpt

#TODO: add keys and codes into associative array
PURPLE=$(tput setaf 5)
BLUE=$(tput setaf 4)
CYAN=$(tput setaf 6)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
RED=$(tput setaf 1)
WHITE=$(tput setaf 8)
BLACK=$(tput setaf 0)
DEFAULT=$(tput sgr0)

WHITEBG=$(tput smso)
RESETBG=$(tput sgr0)
UNDERLINE=$(tput smul)

# Main Vars
VMName="$1"
GPUType="${2^^}"

# Network Vars
netName="default"
netPath="/tmp/$netName.xml"

# Storage Vars
DiskPath="/etc/sGPUpt/qemu-images"
ISOPath="/etc/sGPUpt/iso/"
#DiskPath=/home/$SUDO_USER/Documents/qemu-images
#ISOPath=/home/$SUDO_USER/Documents/iso/

# Hooks Vars
pHookVM="/etc/libvirt/hooks/qemu.d/$VMName"
fHook="/etc/libvirt/hooks/qemu"
fHookStart="/etc/libvirt/hooks/qemu.d/$VMName/prepare/begin/start.sh"
fHookEnd="/etc/libvirt/hooks/qemu.d/$VMName/release/end/stop.sh"

# Compile Vars
qemuBranch="v7.2.0"
qemuDir="/etc/sGPUpt/qemu-emulator"
edkBranch="edk2-stable202211"
edkDir="/etc/sGPUpt/edk-compile"

logFile="/home/$SUDO_USER/Desktop/sGPUpt.log"
tab="$(printf '\t')"
virtIO_url="https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"

function header(){
  #TODO: parameterize offset width
  url="https://github.com/$author/$tool/issues"
  rep="Report issues @ $url"
  tag="${RED}♥${DEFAULT} $tool made by $author ${RED}♥${DEFAULT}"
  blen=$(<<< $rep wc -m)
  row=$((blen+3))
  tlen=$(<<< $tag wc -m)
  clen=$(echo -n "${RED}" | wc -m)
  dlen=$(echo -n "${DEFAULT}" | wc -m)
  tlen=$((tlen-((clen*2))-((dlen*2))))
  pad=$((row-tlen))
  hpad=$((pad/2))
  border(){
     printf "\n"
     for((i=0;i<$row;i++)); do
       printf "#"
     done
  }
  hpadded(){
     for((i=0;i<$hpad;i++)); do
       printf " "
     done
  }
  border
  printf "\n#%s%s%${hpad}s#\n" "$(hpadded)" "$tag"
  printf "# %s #" "$rep"
  border
  printf "\n"
}
function logger(){
  pref="[sGPUpt]"
  case "$1" in
    success)
      flag=INFO
      col=GREEN
      ;;
    info)
      flag=INFO
      col=YELLOW
      ;;
    warn)
      flag=WARN
      col=YELLOW
      ;;
    error)
      flag=ERROR
      col=RED
      ;;
  esac
  printf "%s${!col}[%s]${DEFAULT} %s\n" "$pref" $flag "$2"
  [[ "$1" == "error" ]] && exit 1
}

function main()
{
  if [[ $(whoami) != "root" ]]; then
    logger error "This script requires root privileges!"
  elif [[ -z $VMName || -z $GPUType || $GPUType != @("NVIDIA"|"AMD") ]]; then
    logger error "Usage: sudo ./sGPUpt.sh \"{VM-Name}\" <NVIDIA|AMD>"
  elif [[ $VMName =~ " " ]]; then
    logger error "Your machine's name cannot contain the character: ' '"
  elif [[ $VMName =~ "/" ]]; then
    logger error "Your machine's name cannot contain the character: '/'"
  elif [[ -z $(grep -E -m 1 "svm|vmx" /proc/cpuinfo) ]]; then
    logger error "This system doesn't support virtualization, please enable it then run this script again!"
  elif [[ ! -e /sys/firmware/efi ]]; then
    logger error "This system isn't installed in UEFI mode!"
  elif [[ -z $(ls -A /sys/class/iommu/) ]]; then
    logger error "This system doesn't support IOMMU, please enable it then run this script again!"
  fi

  header

  # Start logging
  > $logFile

  # Call Funcs
  QuerySysInfo
  InstallPackages
  SecurityChecks
  CompileChecks
  SetupLibvirt
  SetupHooks
  CreateVM

  # End Information
  logger info "Add your desired OS, then start your VM with Virt Manager or 'sudo virsh start'"

  # NEEDED TO FIX DEBIAN-BASED DISTROS USING VIRT-MANAGER
  if [[ $firstInstall == "true" ]]; then
    read -p "$(logger info "A reboot is required for this distro, reboot now? [Y/n]: ")" CHOICE
    case "$CHOICE" in
      y|Y) reboot ;;
      "") reboot ;;
    esac
  fi
}

function InstallPackages()
{
  source /etc/os-release
  arch_depends=(
    "qemu-base"
    "virt-manager"
    "virt-viewer"
    "dnsmasq"
    "vde2"
    "bridge-utils"
    "openbsd-netcat"
    "libguestfs"
    "swtpm"
    "git"
    "make"
    "ninja"
    "nasm"
    "iasl"
    "pkg-config"
    "spice-protocol"
  )
  alma_depends=(
    "qemu-kvm"
    "virt-manager"
    "virt-viewer"
    "virt-install"
    "libvirt-daemon-config-network"
    "libvirt-daemon-kvm"
    "swtpm"
    "git"
    "make"
    "gcc"
    "g++"
    "ninja-build"
    "nasm"
    "iasl"
    "libuuid-devel"
    "glib2-devel"
    "pixman-devel"
    "spice-protocol"
    "spice-server-devel"
  )
  fedora_depends=(
    "qemu-kvm"
    "virt-manager"
    "virt-viewer"
    "virt-install"
    "libvirt-daemon-config-network"
    "libvirt-daemon-kvm"
    "swtpm"
    "g++"
    "ninja-build"
    "nasm"
    "iasl"
    "libuuid-devel"
    "glib2-devel"
    "pixman-devel"
    "spice-protocol"
    "spice-server-devel"
  )
  debian_depends=(
    "qemu-kvm"
    "virt-manager"
    "virt-viewer"
    "libvirt-daemon-system"
    "libvirt-clients"
    "bridge-utils"
    "swtpm"
    "mesa-utils"
    "git"
    "ninja-build"
    "nasm"
    "iasl"
    "pkg-config"
    "libglib2.0-dev"
    "libpixman-1-dev"
    "meson"
    "build-essential"
    "uuid-dev"
    "python-is-python3"
    "libspice-protocol-dev"
    "libspice-server-dev"
  )
  ubuntu_version=("22.04" "22.10")
  mint_version=("21.1")
  pop_version=("22.04")
  alma_version=("9.1")
  fedora_version=("36" "37")
  local re="\\b$VERSION_ID\\b"

  testVersions() {
    local -n arr="${1}_version"
    if [[ ! ${arr[*]} =~ $re ]]; then
      logger error "This script is only verified to work on $NAME Version $(printf "%s " "${arr[@]}")"
    fi
  }

  # Which Distro
  if [[ -e /etc/arch-release ]]; then
    echo yes | pacman -S --needed "${arch_depends[@]}" >> $logFile 2>&1
  elif [[ -e /etc/debian_version ]]; then
    case $NAME in
      "Ubuntu") arr=ubuntu ;;
      "Linux Mint") arr=mint ;;
      "Pop!_OS") arr=pop ;;
    esac
    testVersions "$arr"
    apt install -y "${debian_depends[@]}" >> $logFile 2>&1
  elif [[ -e /etc/system-release ]]; then
    case $NAME in
      "AlmaLinux")
        testVersions "alma"
        dnf --enablerepo=crb install -y "${alma_depends[@]}" >> $logFile 2>&1
        ;;
      "Fedora"|"Nobara Linux")
        testVersions "fedora"
        dnf install -y "${fedora_depends[@]}" >> $logFile 2>&1
        ;;
    esac
  else
    logger error "Cannot find distro!"
  fi

  # Fedora and Alma don't have libvirt-qemu for some reason?
  case "$NAME" in
    "Fedora"|"AlmaLinux"|"Nobara Linux") groupName=$SUDO_USER ;;
    *) groupName="libvirt-qemu" ;;
  esac

  # If dir doesn't exist then create it
  if [[ ! -e $ISOPath ]]; then
    mkdir -p $ISOPath >> $logFile 2>&1
  fi

  # Download VirtIO Drivers
  if [[ ! -e $ISOPath/virtio-win.iso ]]; then
    logger info "Downloading VirtIO Drivers ISO..."
    wget -P $ISOPath "$virtIO_url" 2>&1 | grep -i "error" >> $logFile 2>&1
  fi
}

function SecurityChecks()
{
  ############################################################################################
  #                                                                                          #
  # Disabling security for virtualization generally isn't a smart idea but since this script #
  # targets home systems it's well worth the trade-off to disable security for ease of use.  #
  #                                                                                          #
  ############################################################################################

  # Disable AppArmor
  if [[ $NAME =~ ("Ubuntu"|"Pop!_OS"|"Linux Mint") ]] && [[ ! -e /etc/apparmor.d/disable/usr.sbin.libvirtd ]]; then
    local armor="/etc/apparmor.d/usr/sbin.libvirtd"
    firstInstall="true" # NEEDED TO FIX DEBIAN-BASED DISTROS USING VIRT-MANAGER
    logger info "Disabling AppArmor permanently for this distro"
    ln -s "$armor" /etc/apparmor.d/disable/ >> $logFile 2>&1
    apparmor_parser -R "$armor" >> $logFile 2>&1
  fi

  # Disable SELinux
  if [[ $NAME =~ ("Fedora"|"AlmaLinux"|"Nobara Linux") ]]; then
    local se_config="/etc/selinux/config"
    source "$se_config"
    if [[ $SELINUX == "enforcing" ]]; then
      logger info "Disabling SELinux permanently for this distro"
      setenforce 0 >> $logFile 2>&1
      sed -i "s/SELINUX=enforcing/SELINUX=disabled/" "$se_config" >> $logFile 2>&1
    fi
  fi
}

function CompileChecks()
{
  local status_file="/etc/sGPUpt/install-status.txt"
  stat(){
    echo "$1" > "$status_file"
  }
  # Create a file for checking if the compiled qemu was previously installed.
  if [[ ! -e "$status_file" ]]; then
    touch "$status_file"
  fi

  # Compile Spoofed QEMU & EDK2 OVMF
  if [[ ! -e $qemuDir/build/qemu-system-x86_64 ]]; then
    logger info "Starting QEMU compile... please wait."
    stat 0
    QemuCompile
  fi

  if [[ ! -e $edkDir/Build/OvmfX64/RELEASE_GCC5/FV/OVMF_CODE.fd ]]; then
    logger info "Starting EDK2 compile... please wait."
    EDK2Compile
  fi

  # symlink for OVMF
  if [[ ! -e /etc/sGPUpt/OVMF_CODE.fd ]]; then
    ln -s $edkDir/Build/OvmfX64/RELEASE_GCC5/FV/OVMF_CODE.fd /etc/sGPUpt/OVMF_CODE.fd >> $logFile 2>&1
  fi

  # symlink for QEMU
  if [[ ! -e /etc/sGPUpt/qemu-system-x86_64 ]]; then
    ln -s $qemuDir/build/qemu-system-x86_64 /etc/sGPUpt/qemu-system-x86_64 >> $logFile 2>&1
  fi

  if [[ ! -e $qemuDir/build/qemu-system-x86_64 && ! -e $edkDir/Build/OvmfX64/RELEASE_GCC5/FV/OVMF_CODE.fd ]]; then
    logger error "Failed to compile? Check the log file."
  fi

  if (( $(cat "$status_file") == 0 )); then
    logger info "Finished compiling, installing compiled output..."
    cd $qemuDir >> $logFile 2>&1
    make install >> $logFile 2>&1 # may cause an issue ~ host compains about "Host does not support virtualization"
    stat 1
  fi

  vQEMU=$(/etc/sGPUpt/qemu-system-x86_64 --version | head -n 1 | awk '{print $4}')
}

function QemuCompile()
{
  if [[ -e $qemuDir ]]; then
    rm -rf $qemuDir >> $logFile 2>&1
  fi

  mkdir -p $qemuDir >> $logFile 2>&1
  git clone --branch $qemuBranch https://github.com/qemu/qemu.git $qemuDir >> $logFile 2>&1
  cd $qemuDir >> $logFile 2>&1

  # Spoofing edits ~ We should probably add a bit more here...
  sed -i 's/BOCHS /ALASKA/'                                                                 $qemuDir/include/hw/acpi/aml-build.h
  sed -i 's/BXPC    /ASPC    /'                                                             $qemuDir/include/hw/acpi/aml-build.h
  sed -i 's/QEMU HARDDISK/WDC WD10JPVX-22JC3T0/'                                            $qemuDir/hw/scsi/scsi-disk.c
  sed -i 's/QEMU HARDDISK/WDC WD10JPVX-22JC3T0/'                                            $qemuDir/hw/ide/core.c
  sed -i 's/QEMU DVD-ROM/ASUS DRW 24F1ST/'                                                  $qemuDir/hw/ide/core.c
  sed -i 's/QEMU/ASUS/'                                                                     $qemuDir/hw/ide/atapi.c
  sed -i 's/QEMU DVD-ROM/ASUS DRW 24F1ST/'                                                  $qemuDir/hw/ide/atapi.c
  sed -i 's/QEMU PenPartner Tablet/Wacom Tablet/'                                           $qemuDir/hw/usb/dev-wacom.c
  sed -i 's/QEMU PenPartner Tablet/Wacom Tablet/'                                           $qemuDir/hw/scsi/scsi-disk.c
  sed -i 's/#define DEFAULT_CPU_SPEED 2000/#define DEFAULT_CPU_SPEED 3400/'                 $qemuDir/hw/scsi/scsi-disk.c
  sed -i 's/KVMKVMKVM\0\0\0/$CPUBrand/'                                                     $qemuDir/include/standard-headers/asm-x86/kvm_para.h
  sed -i 's/KVMKVMKVM\0\0\0/$CPUBrand/'                                                     $qemuDir/target/i386/kvm/kvm.c
  sed -i 's/bochs/AMI/'                                                                     $qemuDir/block/bochs.c

  ./configure --enable-spice --disable-werror >> $logFile 2>&1
  make -j$(nproc) >> $logFile 2>&1

  chown -R $SUDO_USER:$SUDO_USER $qemuDir >> $logFile 2>&1
}

function EDK2Compile()
{
  if [[ -e $edkDir ]]; then
    rm -rf $edkDir >> $logFile 2>&1
  fi

  mkdir -p $edkDir >> $logFile 2>&1
  cd $edkDir >> $logFile 2>&1

  git clone --branch $edkBranch https://github.com/tianocore/edk2.git $edkDir >> $logFile 2>&1
  git submodule update --init >> $logFile 2>&1

  # Spoofing edits
  sed -i 's/EDK II/American Megatrends/'                                                    $edkDir/MdeModulePkg/MdeModulePkg.dec
  sed -i 's/EDK II/American Megatrends/'                                                    $edkDir/ShellPkg/ShellPkg.dec

  make -j$(nproc) -C BaseTools >> $logFile 2>&1
  . edksetup.sh >> $logFile 2>&1
  OvmfPkg/build.sh -p OvmfPkg/OvmfPkgX64.dsc -a X64 -b RELEASE -t GCC5 >> $logFile 2>&1

  chown -R $SUDO_USER:$SUDO_USER $edkDir >> $logFile 2>&1
}

function QuerySysInfo()
{
  # Base CPU Information
  CPUBrand=$(grep -m 1 'vendor_id' /proc/cpuinfo | cut -c13-)
  CPUName=$(grep -m 1 'model name' /proc/cpuinfo | cut -c14-)

  case $CPUBrand in
    "AuthenticAMD") SysType="AMD" ;;
    "GenuineIntel") SysType="Intel" ;;
    *) logger error "Failed to find CPU brand." ;;
  esac

  # Core + Thread Pairs
  for (( i=0, u=0; i<$(nproc) / 2; i++ )); do
    PT=$(lscpu -p | tail -n +5 | grep ",,[0-9]*,[0-9]*,$i,[0-9]*" | cut -d"," -f1)

    ((p=1))
    for core in $PT; do
      aCPU[$u]=$(echo $PT | cut -d" " -f$p)
      ((u++, p++))
    done
  done

  # Used for isolation in start.sh & end.sh
  ReservedCPUs="$(echo $PT | tr " " ",")"
  AllCPUs="0-$(($(nproc)-1))"

  # Stop the script if we have more than one GPU in the system
  local lines=$(lspci | grep -c VGA)
  if [[ $lines -gt 1 ]]; then
    logger error "There are too many GPUs in the system!"
  fi

  # Determine which GPU type
  if [[ $GPUType == "NVIDIA" ]]; then
    grepGPU="NVIDIA"
    GPUName=${GREEN}$(glxinfo -B | grep "renderer string" | cut -d":" -f2 | cut -c2- | cut -d"/" -f1)${DEFAULT}
  elif [[ $GPUType == "AMD" ]]; then
    grepGPU="AMD/ATI"
    GPUName=${RED}$(glxinfo -B | grep "renderer string" | cut -d":" -f2 | cut -c2- | cut -d"(" -f1 | head -c -2)${DEFAULT}
  fi

  # Get passthrough devices
  CheckIOMMUGroups

  # Stop the script if any of these variables are undefined
  if [[ -z ${aGPU[0]} || -z ${aGPU[1]} ]]; then
    logger error "Couldn't find any GPU on the system..."
  elif [[ -z $GPUName ]]; then
    logger error "Failed to find GPU name, do you have drivers installed?"
  elif [[ -z $aUSB ]]; then
    logger error "Couldn't find any USB controllers on the system..."
  fi

  read -p "$(logger info "Is this the correct GPU? [ $GPUName ]") [y/N]: " CHOICE
  if [[ $CHOICE != @("y"|"Y") ]]; then
    logger error "Please report this if your GPU wasn't detected correctly!"
  fi

  # CPU topology
  for core in $PT; do ((int+=1)); done
  vThread=$(lscpu | grep "Thread(s)" | awk '{print $4}')
  vCPU=$(($(nproc) - $int))
  vCore=$(($vCPU / $vThread))

  # Get the hosts total memory to split for the VM
  SysMem=$(free -g | grep -oP '\d+' | head -n 1)
  if [[ $SysMem -gt 120 ]]; then
    vMem="65536"
  elif [[ $SysMem -gt 90 ]]; then
    vMem="49152"
  elif [[ $SysMem -gt 60 ]]; then
    vMem="32768"
  elif [[ $SysMem -gt 30 ]]; then
    vMem="16384"
  elif [[ $SysMem -gt 20 ]]; then
    vMem="12288"
  elif [[ $SysMem -gt 14 ]]; then
    vMem="8192"
  elif [[ $SysMem -gt 10 ]]; then
    vMem="6144"
  else
    vMem="4096"
  fi

	cat <<- 'DOC' >> $logFile
    ["Query Result"]
    {
      "System Conf":[
      {
        "CPU":[
        {
          "ID":"$CPUBrand",
          "Name":"$CPUName",
          "CPU Pinning": [ "${aCPU[@]}" ]
        }],

        "Sys.Memory":"$SysMem",

        "Isolation":[
        {
          "ReservedCPUs":"$ReservedCPUs",
          "AllCPUs":"$AllCPUs"
        }],

        "PCI":[
        {
          "GPU Name":"$(<<< $GPUName sed -r 's/\x1B\[([0-9]{1,3}(;[0-9]{1,2};?)?)?[mGK]//g')",
          "GPU IDs": [ ${aGPU[@]} ],
          "USB IDs": [ ${aUSB[@]} ]
        }],
      }],

      "Virt Conf":[
      {
        "vCPUs":"$vCPU",
        "vCores":"$vCore",
        "vThreads":"$vThread",
        "vMem":"$vMem",
        "Converted GPU IDs ": [ ${aConvertedGPU[@]} ],
        "USB IDs": [ ${aConvertedUSB[@]} ]
      }]
    }
	DOC
}

###############################################################################
# Refer to the link below if you need to understand this function             #
# https://wiki.archlinux.org/title/PCI_passthrough_via_OVMF#Setting_up_IOMMU  #
###############################################################################
function CheckIOMMUGroups()
{
  ((h=0, allocateGPUOnCycle=0))
  for g in $(find /sys/kernel/iommu_groups/* -maxdepth 0 -type d | sort -V); do

    # Check each device in the group to ensure that our target device is isolated properly
    for d in $g/devices/*; do
      deviceID=$(echo ${d##*/} | cut -c6-)
      deviceOutput=$(lspci -nns $deviceID)
      gr=$(tput setaf 99)${g##*/}$(tput sgr0)
      indicator="$(tput setaf 222)>$(tput sgr0)"
      echo -e "\tGroup $gr - $deviceOutput"

      if [[ $deviceOutput =~ (VGA|Audio) ]] && [[ $deviceOutput =~ $grepGPU ]]; then
         aGPU[$h]=$deviceID
         ((h++, allocateGPUOnCycle=1))
         tput cuu1
         echo -e "      $indicator"
      elif [[ $deviceOutput =~ (USB Controller) ]]; then
         aUSB[$k]=$deviceID
         ((k++))
         tput cuu1
         echo -e "      $indicator"
       else
         ((miscDevice++))
      fi
    done

    # If $aGPU was defined earlier but it turns out to be in an unisolated group then dump the variable
    if [[ ${#aGPU[@]} -gt 0 ]] && [[ $miscDevice -gt 0 ]] && [[ $allocateGPUOnCycle -eq 1 ]]; then
      unset aGPU
    elif [[ ${#aUSB[@]} -gt 0 ]] && [[ $miscDevice -gt 0 ]]; then
      for((m=$((${#aUSB[@]}));m>-1;m--)); do
        unset aUSB[$m]
      done
    fi
    unset miscDevice allocateGPUOnCycle
  done

  local invalid=$(tput setaf 1)invalid$(tput sgr0)
  local valid=$(tput setaf 2)valid$(tput sgr0)
  case ${#aGPU[@]} in
    2) echo -e "GPU: $valid for passthrough! = [ ${aGPU[*]} ]" ;;
    *)
       echo "GPU: $invalid for passthrough!"
       exit 1
       ;;
  esac
  case ${#aUSB[@]} in
    2) echo -e "USB: $valid for passthrough! = [ ${aUSB[*]} ]" ;;
    *)
       echo "USB: $invalid for passthrough!"
       exit 1
       ;;
  esac
  for i in "${!aGPU[@]}"; do
    k=$(<<< ${aGPU[$i]} tr :. _)
    aConvertedGPU[$i]="$k"
  done
  for i in "${!aUSB[@]}"; do
    k=$(<<< ${aUSB[$i]} tr :. _)
    aConvertedUSB[$i]="$k"
  done
}

function SetupHooks()
{
  # If hooks aren't installed
  if [[ ! -e /etc/libvirt/hooks/ ]]; then
    CreateHooks
  fi

  # Is this the first time we're creating hooks for this VM?
  if [[ ! -e $pHookVM ]]; then
    logger info "Creating passthrough hooks..."
  else
    logger info "Recreating passthrough hooks..."
  fi

  # Create start.sh & end.sh
  StartScript
  EndScript

  # Allow hooks to execute
  chmod +x -R $pHookVM >> $logFile 2>&1
}

CreateHooks()
{
  mkdir -p /etc/libvirt/hooks/qemu.d/ >> $logFile 2>&1
  touch    $fHook >> $logFile 2>&1
  chmod +x $fHook >> $logFile 2>&1

  # https://github.com/PassthroughPOST/VFIO-Tools/blob/master/libvirt_hooks/qemu
	cat <<- 'DOC' >> $fHook
    #!/bin/bash
    GUEST_NAME="$1"
    HOOK_NAME="$2"
    STATE_NAME="$3"
    MISC="${@:4}"
    BASEDIR="$(dirname $0)"
    HOOKPATH="$BASEDIR/qemu.d/$GUEST_NAME/$HOOK_NAME/$STATE_NAME"
    set -e
    if [ -f "$HOOKPATH" ] && [ -s "$HOOKPATH" ] && [ -x "$HOOKPATH" ]; then
      eval "$HOOKPATH" "$@"
    elif [ -d "$HOOKPATH" ]; then
      while read file; do
      if [ ! -z "$file" ]; then
        eval "$file" "$@"
      fi
        done <<< "$(find -L "$HOOKPATH" -maxdepth 1 -type f -executable -print;)"
      fi
	DOC
}

function StartScript()
{
  # Create begin hook for VM if it doesn't exist
  if [[ ! -e $pHookVM/prepare/begin/ ]]; then
    mkdir -p $pHookVM/prepare/begin/ >> $logFile 2>&1
    touch    $pHookVM/prepare/begin/start.sh >> $logFile 2>&1
  fi

  > $fHookStart
	cat <<- 'DOC' >> $fHookStart
      #!/bin/bash
      set -x
      systemctl stop display-manager
      if [[ -n \$(pgrep -x "gdm-x-session") ]]; then
        killall gdm-x-session
      elif [[ -n \$(pgrep -x "gdm-wayland-session") ]]; then
        killall gdm-wayland-session
      fi
      for file in /sys/class/vtconsole/*; do
        if (( \$(grep -c \"frame buffer\" \$file/name) == 1 )); then
          echo 0 > \$file/bind
        fi
      done
      # Only needed for some GPUs? I'll mess with this later...
      echo efi-framebuffer.0 > /sys/bus/platform/drivers/efi-framebuffer/unbind
	DOC
      if [[ $GPUType == "NVIDIA" ]]; then
        echo -e "modprobe -r nvidia nvidia_drm nvidia_uvm nvidia_modeset" >> $fHookStart
      elif [[ $GPUType == "AMD" ]]; then
        echo -e "modprobe -r amdgpu" >> $fHookStart
      fi
	cat <<- 'DOC' >> $fHookStart
      virsh nodedev-detach pci_0000_${aConvertedGPU[0]}
      virsh nodedev-detach pci_0000_${aConvertedGPU[1]}
	DOC
      for usb in ${aConvertedUSB[@]}; do
        echo -e "virsh nodedev-detach pci_0000_$usb"
      done >> $fHookStart
	cat <<- 'DOC' >> $fHookStart
      modprobe vfio-pci
      systemctl set-property --runtime -- user.slice AllowedCPUs=$ReservedCPUs
      systemctl set-property --runtime -- system.slice AllowedCPUs=$ReservedCPUs
      systemctl set-property --runtime -- init.scope AllowedCPUs=$ReservedCPUs
	DOC
}

function EndScript()
{
  # Create release hook for VM if it doesn't exist
  if [[ ! -e $pHookVM/release ]]; then
    mkdir -p $pHookVM/release/end/ >> $logFile 2>&1
    touch    $pHookVM/release/end/stop.sh >> $logFile 2>&1
  fi

  > $fHookEnd
	cat <<- 'DOC' >> $fHookEnd
      #!/bin/bash
      set -x
      virsh nodedev-reattach pci_0000_${aConvertedGPU[0]}
      virsh nodedev-reattach pci_0000_${aConvertedGPU[1]}
      modprobe -r vfio_pci
	DOC
      for usb in ${aConvertedUSB[@]}; do
        echo -e "virsh nodedev-reattach pci_0000_$usb"
      done >> $fHookEnd

      if [[ $GPUType == "NVIDIA" ]]; then
        echo -e "modprobe nvidia nvidia_drm nvidia_uvm nvidia_modeset" >> $fHookEnd
      elif [[ $GPUType == "AMD" ]]; then
        echo -e "modprobe amdgpu" >> $fHookEnd
      fi
	cat <<- 'DOC' >> $fHookEnd
      systemctl start display-manager
      for file in /sys/class/vtconsole/*; do
        if (( \$(grep -c "frame buffer" \$file/name) == 1 )); then
          echo 1 > \$file/bind
        fi
      done
      systemctl set-property --runtime -- user.slice AllowedCPUs=$AllCPUs
      systemctl set-property --runtime -- system.slice AllowedCPUs=$AllCPUs
      systemctl set-property --runtime -- init.scope AllowedCPUs=$AllCPUs
	DOC
}

function vNetworkCheck()
{
  # If '$netName' doesn't exist then create it!
  if [[ $(virsh net-autostart $netName 2>&1) =~ "Network not found" ]]; then
    > $netPath
	cat <<- 'DOC' >> $netPath
      <network>
        <name>$netName</name>
        <forward mode="nat">
          <nat>
            <port start="1024" end="65535"/>
          </nat>
        </forward>
        <ip address=192.168.122.1 netmask=255.255.255.0>
          <dhcp>
            <range start=192.168.122.2 end=192.168.122.254/>
          </dhcp>
        </ip>
      </network>
	DOC

    virsh net-define $netPath >> $logFile 2>&1
    rm $netPath >> $logFile 2>&1

    logger info "Network manually created"
  fi

  # set autostart on network '$netName' in case it wasn't already on for some reason
  if [[ $(virsh net-info $netName | grep "Autostart" | awk '{print $2}') == "no" ]]; then
    virsh net-autostart $netName >> $logFile 2>&1
  fi

  # start network if it isn't active
  if [[ $(virsh net-info $netName | grep "Active" | awk '{print $2}') == "no" ]]; then
    virsh net-start $netName >> $logFile 2>&1
  fi
}

function SetupLibvirt()
{
  # If group doesn't exist then create it
  if [[ -z $(getent group libvirt) ]]; then
    groupadd libvirt >> $logFile 2>&1
    logger info "Created libvirt group"
  fi

  # If either user isn't in the group then add all of them again
  if [[ -z $(groups $SUDO_USER | grep libvirt | grep kvm | grep input) ]]; then
    usermod -aG libvirt,kvm,input $SUDO_USER >> $logFile 2>&1
    logger info "Added user '$SUDO_USER' to groups 'libvirt,kvm,input'"
  fi

  # Allow users in group libvirt to use virt-manager /etc/libvirt/libvirtd.conf
  if [[ $(grep 'unix_sock_group = "libvirt"' /etc/libvirt/libvirtd.conf) != 'unix_sock_group = "libvirt"' ]]; then
    sed -i 's/#unix_sock_group = "libvirt"/unix_sock_group = "libvirt"/' /etc/libvirt/libvirtd.conf
  fi

  if [[ $(grep 'unix_sock_rw_perms = "0770"' /etc/libvirt/libvirtd.conf) != 'unix_sock_rw_perms = "0770"' ]]; then
    sed -i 's/#unix_sock_rw_perms = "0770"/unix_sock_rw_perms = "0770"/' /etc/libvirt/libvirtd.conf
  fi

  # Kill virt-manager because it shouldn't opened during the install
  if [[ -n $(pgrep -x "virt-manager") ]]; then
    killall virt-manager
    #echo -e "~ [${PURPLE}sGPUpt${DEFAULT}] ${RED}Killed virt-manager${DEFAULT}"
  fi

  # Restart or enable libvirtd
  if [[ -n $(pgrep -x "libvirtd") ]]; then
    if [[ -e /run/systemd/system ]]; then
      systemctl restart libvirtd.service >> $logFile 2>&1
    else
      rc-service libvirtd.service restart >> $logFile 2>&1
    fi
  else
    if [[ -e /run/systemd/system ]]; then
      systemctl enable --now libvirtd.service >> $logFile 2>&1
    else
      rc-update add libvirtd.service default >> $logFile 2>&1
      rc-service libvirtd.service start >> $logFile 2>&1
    fi
  fi

  vNetworkCheck
}

function CreateVM()
{
  # Overwrite protection for existing VM configurations
  if [[ -e /etc/libvirt/qemu/$VMName.xml ]]; then
    logger info "sGPUpt Will not overwrite an existing VM Config!"
    return
  fi

  # If dir doesn't exist then create it
  if [[ ! -e $DiskPath ]]; then
    mkdir -p $DiskPath >> $logFile 2>&1
  fi

  # Disk img doesn't exist then create it
  if [[ ! -e $DiskPath/$VMName.qcow2 ]]; then
    read -p "$(logger info "Do you want to create a drive named ${VMName}? [y/N]: ")" CHOICE
  else 
    read -p "$(logger info "The drive ${VMName} already exists. Overwrite it? [y/N]: ")" CHOICE
  fi

  case $CHOICE in
    y|Y) HandleDisk
      disk_pretty=" Disk:\"${DiskSize}G\", "
      ;;
    ""|N) disk_pretty=" "
  esac

  case $SysType in
    AMD)    CPUFeatures="hv_vendor_id=AuthenticAMD,-x2apic,+svm,+invtsc,+topoext" ;;
    Intel)  CPUFeatures="hv_vendor_id=GenuineIntel,-x2apic,+vmx" ;;
  esac

  OVMF_CODE="/etc/sGPUpt/OVMF_CODE.fd"
  OVMF_VARS="/var/lib/libvirt/qemu/nvram/${VMName}_VARS.fd"
  Emulator="/etc/sGPUpt/qemu-system-x86_64"
  cp $edkDir/Build/OvmfX64/RELEASE_GCC5/FV/OVMF_VARS.fd $OVMF_VARS

  logger info "Creating VM [ Type:\"$SysType\", Name:\"$VMName\", vCPU:\"$vCPU\", Mem:\"$vMem"\M"\",${disk_pretty}QEMU-V:\"$vQEMU\" ]"

  virt-install \
  --connect qemu:///system \
  --noreboot \
  --noautoconsole \
  --name $VMName \
  --memory $vMem \
  --vcpus $vCPU \
  --osinfo win10 \
  --cpu host-model,topology.dies=1,topology.sockets=1,topology.cores=$vCore,topology.threads=$vThread,check=none \
  --clock rtc_present=no,pit_present=no,hpet_present=no,kvmclock_present=no,hypervclock_present=yes,timer5.name=tsc,timer5.present=yes,timer5.mode=native \
  --boot loader.readonly=yes,loader.type=pflash,loader=$OVMF_CODE \
  --boot nvram=$OVMF_VARS \
  --boot emulator=$Emulator \
  --boot cdrom,hd,menu=on \
  --feature vmport.state=off \
  --disk device=cdrom,path=$ISOPath/virtio-win.iso \
  --import \
  --network type=network,source=$netName,model=virtio \
  --sound none \
  --console none \
  --graphics none \
  --controller type=usb,model=none \
  --memballoon model=none \
  --tpm model=tpm-crb,type=emulator,version=2.0 \
  --host-device="pci_0000_${aConvertedGPU[0]}" \
  --host-device="pci_0000_${aConvertedGPU[1]}" \
  --qemu-commandline="-cpu" \
  --qemu-commandline="host,hv_time,hv_relaxed,hv_vapic,hv_spinlocks=8191,hv_vpindex,hv_reset,hv_synic,hv_stimer,hv_frequencies,hv_reenlightenment,hv_tlbflush,hv_ipi,kvm=off,kvm-hint-dedicated=on,-hypervisor,$CPUFeatures" \
  >> $logFile 2>&1

  if [[ $includeDrive == "1" ]]; then
    virt-xml $VMName --add-device --disk path=$DiskPath/$VMName.qcow2,bus=virtio,cache=none,discard=ignore,format=qcow2,bus=sata >> $logFile 2>&1
  fi

  # VM edits
  InsertSpoofedBoard
  InsertCPUPinning
  InsertUSB

  logger success "Finished creating $VMName!"
}

function HandleDisk()
{
  read -p "$(logger info "Size of disk (GB)[default 128]: ")" DiskSize
  
  # If reply is blank/invalid then default to 128G
  if [[ ! $DiskSize =~ ^[0-9]+$ ]] || (( $DiskSize < 1 )); then
    DiskSize="128"
  fi

  qemu-img create -f qcow2 $DiskPath/$VMName.qcow2 ${DiskSize}G >> $logFile 2>&1
  chown $SUDO_USER:$groupName $DiskPath/$VMName.qcow2 >> $logFile 2>&1
  includeDrive="1"
}

function InsertSpoofedBoard()
{
  ASUSMotherboards

  logger info "Spoofing motherboard"

  virt-xml $VMName --add-device --sysinfo bios.vendor="$BIOSVendor",bios.version="$BIOSRandVersion",bios.date="$BIOSDate",bios.release="$BIOSRandRelease" >> $logFile 2>&1
  virt-xml $VMName --add-device --sysinfo system.manufacturer="$SystemManufacturer",system.product="$SystemProduct",system.version="$SystemVersion",system.serial="$SystemRandSerial",system.uuid="$SystemUUID",system.sku="$SystemSku",system.family="$SystemFamily" >> $logFile 2>&1
  virt-xml $VMName --add-device --sysinfo baseBoard.manufacturer="$BaseBoardManufacturer",baseBoard.product="$BaseBoardProduct",baseBoard.version="$BaseBoardVersion",baseBoard.serial="$BaseBoardRandSerial",baseBoard.asset="$BaseBoardAsset",baseBoard.location="$BaseBoardLocation" >> $logFile 2>&1
  virt-xml $VMName --add-device --sysinfo chassis.manufacturer="$ChassisManufacturer",chassis.version="$ChassisVersion",chassis.serial="$ChassisSerial",chassis.asset="$ChassisAsset",chassis.sku="$ChassisSku" >> $logFile 2>&1
  virt-xml $VMName --add-device --sysinfo oemStrings.entry0="$oemStrings0",oemStrings.entry1="$oemStrings1" >> $logFile 2>&1
}

function InsertCPUPinning()
{
  logger info "Adding CPU Pinning for [ $CPUName ]..."
  for (( i=0; i<$vCPU; i++ )); do
    virt-xml $VMName --edit --cputune="vcpupin$i.vcpu=$i,vcpupin$i.cpuset=${aCPU[$i]}" >> $logFile 2>&1
  done
}

function InsertUSB()
{
  logger info "Adding USB Controllers...."
  for usb in ${aConvertedUSB[@]}; do
    virt-xml $VMName --add-device --host-device="pci_0000_$usb" >> $logFile 2>&1
  done
}

function ASUSMotherboards()
{
  ASUSBoards=(
  "TUF GAMING X570-PRO WIFI II"
  "TUF GAMING X570-PLUS (WI-FI)"
  "TUF GAMING X570-PLUS"
  "PRIME X570-PRO"
  "PRIME X570-PRO/CSM"
  "PRIME X570-P"
  "PRIME X570-P/CSM"
  "ROG CROSSHAIR VIII EXTREME"
  "ROG CROSSHAIR VIII DARK HERO"
  "ROG CROSSHAIR VIII FORMULA"
  "ROG CROSSHAIR VIII HERO (WI-FI)"
  "ROG CROSSHAIR VIII HERO"
  "ROG CROSSHAIR VIII IMPACT"
  "ROG STRIX X570-E GAMING WIFI II"
  "ROG STRIX X570-E GAMING"
  "ROG STRIX X570-F GAMING"
  "ROG STRIX X570-I GAMING"
  "PROART X570-CREATOR WIFI"
  "PRO WS X570-ACE"
  )

  BIOSVendor="American Megatrends Inc."
  BIOSDate=$(shuf -i 1-12 -n 1)/$(shuf -i 1-31 -n 1)/$(shuf -i 2015-2023 -n 1)
  BIOSRandVersion=$(shuf -i 3200-4600 -n 1)
  BIOSRandRelease=$(shuf -i 1-6 -n 1).$((15 * $(shuf -i 1-6 -n 1)))

  SystemUUID=$(virsh domuuid $VMName)
  SystemManufacturer="System manufacturer"
  SystemProduct="System Product Name"
  SystemVersion="System Version"
  SystemRandSerial=$(shuf -i 2000000000000-3000000000000 -n 1)
  SystemSku="SKU"
  SystemFamily="To be filled by O.E.M."

  BaseBoardManufacturer="ASUSTeK COMPUTER INC."
  BaseBoardProduct=${ASUSBoards[$(shuf -i 0-$((${#ASUSBoards[@]} - 1)) -n 1)]}
  BaseBoardVersion="Rev X.0x"
  BaseBoardRandSerial=$(shuf -i 200000000000000-300000000000000 -n 1)
  BaseBoardAsset="Default string"
  BaseBoardLocation="Default string"

  ChassisManufacturer="Default string"
  ChassisVersion="Default string"
  ChassisSerial="Default string"
  ChassisAsset="Default string"
  ChassisSku="Default string"

  oemStrings0="Default string"
  oemStrings1="TEQUILA"
}
main
