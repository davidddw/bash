#!/bin/bash

ARGS=2
E_BADARGS=65

if [ $# -ne $ARGS ]  # Correct number of arguments passed to script?
then
    echo "Usage: `basename $0` <image_path> <template_path>"
    exit $E_BADARGS
fi

image_name=SR_Local
image_path=$1
template_name=template
template_path=$2

add_pool()
{   
    cat << EOF > /tmp/local_pool.xml 
<pool type="dir">
  <name>$image_name</name>
  <target>
    <path>$image_path</path>
  </target>
</pool>
EOF
    virsh pool-define /tmp/local_pool.xml
    virsh pool-start $image_name
    virsh pool-autostart $image_name

    cat << EOF > /tmp/template_pool.xml 
<pool type="dir">
  <name>$template_name</name>
  <target>
    <path>$template_path</path>
  </target>
</pool>
EOF
    virsh pool-define /tmp/template_pool.xml
    virsh pool-start $template_name
    virsh pool-autostart $template_name
}

add_pool

rm -rf /tmp/local_pool.xml /tmp/template_pool.xml 
echo Done
exit 0