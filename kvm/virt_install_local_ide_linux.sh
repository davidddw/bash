#!/bin/bash

ARGS=4
E_BADARGS=65

if [ $# -ne $ARGS ]  # Correct number of arguments passed to script?
then
    echo "Usage: `basename $0` <vm_name> <image_path> <size G> <iso>"
    exit $E_BADARGS
fi

KVM_NAME=$1
DISK_PATH=$2
DISK_SIZE=$3
ISO_PATH=$4
/usr/bin/qemu-img create -f qcow2 $DISK_PATH $DISK_SIZE
/usr/bin/virt-install \
    --name $KVM_NAME \
    --vcpus 2 \
    --ram 4096 \
    --os-type=linux \
    --os-variant=rhel6 \
    --disk path=${DISK_PATH},device=disk,format=qcow2,bus=ide \
    --network network=nspbr1,model=virtio \
    --channel unix,path=/var/lib/libvirt/qemu/channel/target/org.\
qemu.guest_agent,mode=bind,target_type=virtio,name=org.qemu.guest_agent.0 \
    --console pty,target_type=serial \
    --accelerate \
    --virt-type=kvm \
    --noreboot \
    --vnc \
    --vnclisten=0.0.0.0 \
    --noautoconsole \
    -c $ISO_PATH

echo Done
exit 0
