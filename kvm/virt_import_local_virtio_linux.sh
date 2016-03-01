#!/bin/bash

ARGS=2
E_BADARGS=65
CONFIG_PATH=/etc/sysconfig/network-scripts

if [ $# -ne $ARGS ]  # Correct number of arguments passed to script?
then
    echo "Usage: `basename $0` <vm_name> <image_path>"
    exit $E_BADARGS
fi

KVM_NAME=$1
DISK_PATH=$2
/usr/bin/virt-install \
    --name $KVM_NAME \
    --vcpus 4 \
    --ram 4096 \
    --os-type=linux  \
    --os-variant=rhel6  \
    --disk path=${DISK_PATH},device=disk,format=qcow2,bus=scsi \
    --controller scsi,model=virtio-scsi \
    --disk device=cdrom \
    --network network=nspbr0,model=virtio \
    --channel unix,path=/var/lib/libvirt/qemu/channel/target/org.\
qemu.guest_agent,mode=bind,target_type=virtio,name=org.qemu.guest_agent.0 \
    --console pty,target_type=serial \
    --accelerate \
    --virt-type=kvm \
    --noreboot \
    --vnc \
    --vnclisten=0.0.0.0 \
    --noautoconsole \
    --import

echo Done
exit 0