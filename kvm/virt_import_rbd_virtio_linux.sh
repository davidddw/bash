#!/bin/bash

set -x

ARGS=3
E_BADARGS=65

if [ $# -ne $ARGS ]  # Correct number of arguments passed to script?
then
    echo "Usage: `basename $0` <vm_name> <image_path> <mon1,mon2>"
    exit $E_BADARGS
fi

KVM_NAME=$1
DISK_PATH=$2
MON_IP=$3

/usr/bin/virt-install \
    --name $KVM_NAME \
    --vcpus 4 \
    --ram 4096 \
    --os-type=linux  \
    --os-variant=rhel6  \
    --controller scsi,model=virtio-scsi \
    --nodisks \
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
    --boot hd

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
echo "  <target dev='sda' bus='scsi'/>" >> /tmp/rbd_virtdisk.xml
echo "</disk>" >> /tmp/rbd_virtdisk.xml

virsh attach-device $KVM_NAME /tmp/rbd_virtdisk.xml --persistent

echo Done
exit 0