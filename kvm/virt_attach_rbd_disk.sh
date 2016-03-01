#!/bin/bash

ARGS=4
E_BADARGS=65
CONFIG_PATH=/etc/sysconfig/network-scripts

if [ $# -ne $ARGS ]  # Correct number of arguments passed to script?
then
    echo "Usage: `basename $0` <vm_name> <image_path> <target vdb> <mon ip>"
    exit $E_BADARGS
fi

KVM_NAME=$1
DISK_PATH=$2
VIRT_DISK=$3
MON_IP=$4

cat << EOF > /tmp/rbd_virtdisk.xml
<disk type='network' device='disk'>
  <driver name='qemu' type='raw'/>
  <source protocol='rbd' name='$DISK_PATH'>
    <host name='${MON_IP}' port='6789'/>
  </source>
  <target dev='${VIRT_DISK}' bus='scsi'/>
</disk>
EOF

virsh attach-device $KVM_NAME /tmp/rbd_virtdisk.xml --persistent

echo Done
exit 0