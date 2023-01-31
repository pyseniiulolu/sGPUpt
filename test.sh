#!/bin/bash
GPUType=NVIDIA
function CheckIOMMUGroupsTest()
{
  ((h=0, allocateGPUOnCycle=0))
  case $GPUType in
   NVIDIA) GrepGPU="NVIDIA" ;;
   AMD) GrepGPU="AMD/ATI" ;;
  esac
  for g in $(find /sys/kernel/iommu_groups/* -maxdepth 0 -type d | sort -V); do

    # Check each device in the group to ensure that our target device is isolated properly
    for d in $g/devices/*; do
      deviceID=$(echo ${d##*/} | cut -c6-)
      deviceOutput=$(lspci -nns $deviceID)
      gr=$(tput setaf 99)${g##*/}$(tput sgr0)
      echo -e "\tGroup $gr - $deviceOutput"

      # If the device isn't part of our GPU then continue checking group
      if [[ $deviceOutput =~ (VGA|Audio) ]] && [[ $deviceOutput =~ $GrepGPU ]]; then
         aGPU[$h]=$deviceID
         ((h++, allocateGPUOnCycle=1))
         tput cuu1
         echo -e "      $(tput setaf 2)>$(tput sgr0)"
      elif [[ $deviceOutput =~ (USB Controller) ]]; then
         aUSB[$k]=$deviceID
         ((k++))
       else
         ((miscDevice++))
      fi
    done

    # If $aGPU was defined earlier but it turns out to be in an unisolated group then dump the variable
    if [[ ${#aGPU[@]} -gt 0 ]] && [[ $miscDevice -gt 0 ]] && [[ $allocateGPUOnCycle -eq 1 ]]; then
      unset aGPU
    elif [[ ${#aUSB[@]} -gt 0 ]] && [[ $miscDevice -gt 0 ]]; then
      for((m=$((${#aUSB[@]}-1));m>-1;m--)); do
        unset aUSB[$m]
      done
    fi
    unset miscDevice allocateGPUOnCycle
  done

  invalid=$(tput setaf 1)invalid$(tput sgr0)
  valid=$(tput setaf 2)valid$(tput sgr0)
  case ${#aGPU[@]} in
    2) echo -e "GPU is $valid for passthrough! = [ ${aGPU[*]} ]" ;;
    *)
       echo "GPU is $invalid for passthrough!"
       exit 1
       ;;
  esac

}

CheckIOMMUGroupsTest
