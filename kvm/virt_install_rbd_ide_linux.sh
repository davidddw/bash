#!/bin/bash

set -x

ARGS=5
E_BADARGS=65

if [ $# -ne $ARGS ]  # Correct number of arguments passed to script?
then
    echo "Usage: `basename $0` <vm_name> <image_path> <size> <iso> <mon>"
    exit $E_BADARGS
fi

KVM_NAME=$1
DISK_PATH=$2
DISK_SIZE=$3
ISO_PATH=$4
MON_IP=$5

rbd create $DISK_PATH --size $DISK_SIZE --stripe-unit 65536 \
--stripe-count 16 --image-format 2
/usr/bin/virt-install \
    --name $KVM_NAME \
    --vcpus 2 \
    --ram 2048 \
    --nodisks \
    --network network=nspbr0,model=virtio \
    --channel unix,path=/var/lib/libvirt/qemu/org.\
qemu.guest_agent,mode=bind,target_type=virtio,name=org.qemu.guest_agent.0 \
    --console pty,target_type=serial \
    --accelerate \
    --virt-type=kvm \
    --noreboot \
    --noautoconsole \
    --vnc \
    --vnclisten=0.0.0.0 \
    --boot cdrom

echo "<disk type='network' device='disk'>" > /tmp/rbd_virtdisk.xml
echo "  <driver name='qemu' type='raw'/>" >> /tmp/rbd_virtdisk.xml
echo "  <source protocol='rbd' name='$DISK_PATH'>" >> /tmp/rbd_virtdisk.xml
IFS=, read -r -a MON_IPS <<< "$MON_IP"
if [[ ${#MON_IPS[@]} -gt 0 ]]; then
    for mon in ${MON_IPS[@]}; do
        echo "    <host name='${mon}' port='6789'/>" >> /tmp/rbd_virtdisk.xml
    done
fi
echo "  </source>" >> /tmp/rbd_virtdisk.xml
echo "  <target dev='hda' bus='ide'/>" >> /tmp/rbd_virtdisk.xml
echo "</disk>" >> /tmp/rbd_virtdisk.xml

virsh attach-device $KVM_NAME /tmp/rbd_virtdisk.xml --config

virsh attach-disk \
    --domain $KVM_NAME \
    --source $ISO_PATH \
    --target hdb \
    --type cdrom \
    --driver qemu \
    --mode readonly \
    --persistent

echo Done
exit 0

# virsh destroy test1 && virsh undefine test1 && rbd rm capacity/test1