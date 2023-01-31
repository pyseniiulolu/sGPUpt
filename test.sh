#!/bin/bash

function CheckIOMMUGroupsTest()
{
  ((h=0, allocateGPUOnCycle=0))

  #if [[ $GPUType == "NVIDIA" ]]; then
    GrepGPU="NVIDIA"
  #elif [[ $GPUType == "AMD" ]]; then
   # GrepGPU="AMD/ATI"
  #fi

  for g in $(find /sys/kernel/iommu_groups/* -maxdepth 0 -type d | sort -V); do

    # Check each device in the group to ensure that our target device is isolated properly
    for d in $g/devices/*; do
      echo -e "\tGroup $(tput setaf 99)${g##*/}$(tput sgr0) - $(lspci -nns ${d##*/})"

      deviceID=$(echo ${d##*/} | cut -c6-)
      deviceOutput=$(lspci -nn -s $deviceID)

      # If the device isn't part of our GPU then continue checking group
      if [[ ! $deviceOutput == @(*"VGA"*|*"Audio"*) ]] || [[ ! $deviceOutput =~ "$GrepGPU" ]]; then
        ((miscDevice+=1))
        continue
      fi

      # If there's *currently* no other device in the group then add the device to the array
      if (( $miscDevice == 0 )); then
        aGPU[$h]=$deviceID
        ((h++, allocateGPUOnCycle=1))
        echo -e "\t+        $(tput setaf 2)✔️$(tput sgr0) ^"
      fi
    done

    # If $aGPU was defined earlier but it turns out to be in an unisolated group then dump the variable
    if [[ -n $aGPU ]] && (( $miscDevice > 0 )) && (( $allocateGPUOnCycle == 1 )); then
      unset aGPU
    fi

    ((miscDevice=0, allocateGPUOnCycle=0))
  done

  if (( ${#aGPU[@]} != 2 )); then
    echo "GPU is not $(tput setaf 1)invalid$(tput sgr0) for passthrough!"
    exit 1
  fi

  echo -e "GPU is $(tput setaf 2)valid$(tput sgr0) for passthrough! = [ ${aGPU[@]} ]"
}

CheckIOMMUGroupsTest
