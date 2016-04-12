#!/bin/sh

#
# Copyright (c) 2014 Yunshan Networks
# All right reserved.
#
# Filename: vm_init.sh
# Author Name: Jin Jie
# Date: 2014-05-15
#
# Description: Linux PVM initialization script
#              extracts parameters from /proc/cmdline
#              updates password, hostname and ip address
#              parameters are:
#                  livecloud.ctrl_dev=eth6
#                  livecloud.ctrl_ip=172.16.11.82/16
#                  livecloud.ctrl_mac=d6:32:05:90:bf:c7
#                  livecloud.srv_mac=3a:01:c3:db:a4:1f
#                  livecloud.init_passwd=security421
#                  livecloud.hostname=example-vm
#                  livecloud.xen_ip=172.16.1.102
#

LOG=/var/log/vm_init.log
CONF=/etc/livecloud.conf
LBCONF=/etc/haproxy/haproxy.cfg

function log() {
    echo "[`date +'%F %T'`] $1" | tee -a $LOG
}

function masklen2netmask() {
    declare -i full_mask=0xffffffff
    declare -i N="$full_mask << (32 - $1)"
    H1=$(($N & 0x000000ff))
    H2=$((($N & 0x0000ff00) >> 8))
    L1=$((($N & 0x00ff0000) >> 16))
    L2=$((($N & 0xff000000) >> 24))
    echo "$L2.$L1.$H2.$H1"
}

function parse_cmdline() {
    HOSTNAME=$1
    DEVICE=$2
    IPADDR=`echo $3 | cut -d/ -f1`
    MASKLEN=`echo $3 | cut -d/ -f2`
    MAC=$4
    SRVDEVICE=$5
    SRVMAC=$6
    PASSWD=$7
    XENIP=$8
    if [[ -z "$HOSTNAME" || -z "$DEVICE" || -z "$IPADDR" ||
          -z "$MASKLEN" || -z "$PASSWD" || -z "$MAC" ||
          -z "$SRVDEVICE" || -z "$SRVMAC" ]]; then
        log "Parameters invalid"
        exit 1
    fi
}

function parse_proc_cmdline() {
    HOSTNAME=
    DEVICE=
    IPADDR=
    MASKLEN=
    MAC=
    SRVMAC=
    PASSWD=
    XENIP=
    options=`cat /proc/cmdline`
    for opt in ${options[@]}; do
        if [[ "$opt" = 'livecloud.'* ]]; then
            key=`echo $opt | cut -d= -f1`
            value=`echo $opt | cut -d= -f2`
            case "$key" in
                livecloud.hostname)
                    HOSTNAME=$value
                    ;;
                livecloud.ctrl_dev)
                    DEVICE=$value
                    ;;
                livecloud.ctrl_ip)
                    IPADDR=`echo $value | cut -d/ -f1`
                    MASKLEN=`echo $value | cut -d/ -f2`
                    ;;
                livecloud.ctrl_mac)
                    MAC=$value
                    ;;
                livecloud.srv_mac)
                    SRVMAC=$value
                    ;;
                livecloud.init_passwd)
                    PASSWD=$value
                    ;;
                livecloud.xen_ip)
                    XENIP=$value
                    ;;
            esac
        fi
    done
    if [[ -z "$HOSTNAME" || -z "$DEVICE" || -z "$IPADDR" ||
          -z "$MASKLEN" || -z "$PASSWD" || -z "$MAC" || -z "$SRVMAC" ]]; then
        log "Parameters invalid"
        exit 1
    fi
}

function bind_ctrl_dev_to_eth6() {
    cat << string >/etc/udev/rules.d/70-persistent-net.rules
SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", ATTR{address}=="$MAC", KERNEL=="eth*", NAME="$DEVICE"
SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", ATTR{address}=="$SRVMAC", KERNEL=="eth*", NAME="eth5"
string
    udevadm control --reload-rules
    udevadm trigger
    ip link set eth2 name $DEVICE
    ip link set eth1 name eth5
}

function config_passwd() {
    echo "root:$PASSWD" | chpasswd
}

function change_centos_ipaddr() {
    cat << string >/etc/sysconfig/network
NETWORKING=yes
HOSTNAME=$HOSTNAME
string
    cat << string >/etc/sysconfig/network-scripts/ifcfg-$DEVICE
DEVICE=$DEVICE
BOOTPROTO=static
HWADDR=$MAC
IPADDR=$IPADDR
NETMASK=`masklen2netmask $MASKLEN`
ONBOOT=yes
string
    which systemctl 2>&1 > /dev/null
    if [[ $? -eq 0 ]]; then
        hostnamectl set-hostname $HOSTNAME
        systemctl restart network
    else
        hostname $HOSTNAME
        service network restart
    fi
}

function change_suse_ipaddr() {
    cat << string >/etc/sysconfig/network/ifcfg-$DEVICE
BOOTPROTO='static'
STARTMODE='onboot'
IPADDR=$IPADDR
NETMASK=`masklen2netmask $MASKLEN`
string
    which systemctl 2>&1 > /dev/null
	if [[ $? -eq 0 ]]; then
	    hostnamectl set-hostname $HOSTNAME
        systemctl restart network
	else
	    hostname $HOSTNAME
	    service network stop
        service network start
	fi
}

function change_debian_ipaddr() {
    echo $HOSTNAME >/etc/hostname
    hostname $HOSTNAME

    cat << string >/etc/network/interfaces
auto lo
iface lo inet loopback

auto $DEVICE
iface $DEVICE inet static
address $IPADDR
netmask `masklen2netmask $MASKLEN`
string

    service networking stop
    service networking start
}

function change_ubuntu_ipaddr() {
    change_debian_ipaddr
    if [[ -n "`echo $issue | grep -i ubuntu | grep -i '14.'`" ]]; then
        ifup $DEVICE
    fi
}

function change_ipaddr() {
    issue=`cat /etc/issue`
    if [[ -n "`echo $issue | grep -iE 'centos|red hat|kernel'`" ]]; then
        change_centos_ipaddr
    elif [[ -n "`echo $issue | grep -i debian`" ]]; then
        change_debian_ipaddr
    elif [[ -n "`echo $issue | grep -i ubuntu`" ]]; then
        change_ubuntu_ipaddr
    elif [[ -n "`echo $issue | grep -i SUSE`" ]]; then
        change_suse_ipaddr
    else
        log "Unknown or not supported system"
    fi
}

function config_centos_vagent_respawn() {
    which systemctl 2>&1 > /dev/null
    if [[ $? -eq 0 ]]; then
        cat << 'string' >/usr/lib/systemd/system/vagent.service
[Unit]
Description=Livecloud vagent
After=syslog.target network.target auditd.service sshd.service

[Service]
ExecStart=/usr/bin/python /usr/local/vagent/vagent.py -d -l
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
string
        systemctl enable vagent.service
        systemctl restart vagent.service
    else
        cat << string >/etc/init/vagent.conf
start on runlevel [2345]
stop on runlevel [!2345]
instance vagent
respawn
exec /usr/bin/python /usr/local/vagent/vagent.py -d -l
string
        initctl start vagent >/dev/null 2>&1
    fi
}

function config_centos5_vagent_respawn() {
    sed -i '/^va:/d' /etc/inittab
    echo 'va:2345:respawn:/usr/bin/python26 /usr/local/vagent/vagent.py -d -l' >>/etc/inittab
    init q
}

function config_debian_vagent_respawn() {
    which systemctl 2>&1 > /dev/null
    if [[ $? -eq 0 ]]; then
        cat << 'string' > /lib/systemd/system/vagent.service
[Unit]
Description=Livecloud vagent
After=syslog.target network.target auditd.service sshd.service

[Service]
ExecStart=/usr/bin/python /usr/local/vagent/vagent.py -d -l
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
string
        systemctl enable vagent.service
        systemctl restart vagent.service
    else
        sed -i '/^va:/d' /etc/inittab
        echo 'va:2345:respawn:/usr/bin/python /usr/local/vagent/vagent.py -d -l' >>/etc/inittab
        init q
    fi
}

function config_ubuntu_vagent_respawn() {
    which systemctl 2>&1 > /dev/null
    if [[ $? -eq 0 ]]; then
        cat << 'string' > /lib/systemd/system/vagent.service
[Unit]
Description=Livecloud vagent
After=syslog.target network.target auditd.service sshd.service

[Service]
ExecStart=/usr/bin/python /usr/local/vagent/vagent.py -d -l
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
string
        systemctl enable vagent.service
        systemctl restart vagent.service
    else
        cat << string >/etc/init/vagent.conf
start on runlevel [2345]
stop on runlevel [!2345]
instance vagent
respawn
exec /usr/bin/python /usr/local/vagent/vagent.py -d -l
string
        start vagent >/dev/null 2>&1
    fi
}

function config_suse_vagent_respawn() {
    which systemctl 2>&1 > /dev/null
    if [[ $? -eq 0 ]]; then
        cat << 'string' >/usr/lib/systemd/system/vagent.service
[Unit]
Description=Livecloud vagent
After=syslog.target network.target auditd.service sshd.service

[Service]
ExecStart=/usr/bin/python /usr/local/vagent/vagent.py -d -l
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
string
        systemctl enable vagent.service
        systemctl restart vagent.service
    else
        sed -i '/^va:/d' /etc/inittab
        echo 'va:2345:respawn:/usr/bin/python /usr/local/vagent/vagent.py -d -l' >>/etc/inittab
        init q
    fi
}

function install_vagent() {
    directory=`pwd`
    cd /usr/local
    /usr/bin/wget http://$XENIP:20016/v1/static/vagent.tar.gz >/dev/null 2>&1
    if [[ $? -ne 0 || ! -f "./vagent.tar.gz" ]]; then
        log "Download vagent.tar.gz error"
        exit 1
    fi
    tar xzf vagent.tar.gz
    rm -f vagent.tar.gz
    cd $directory

    issue=`cat /etc/issue`
    if [[ -n "`echo $issue | grep -iE 'centos|red hat|kernel'`" ]]; then
        release=`cat /etc/redhat-release`
        if [[ -n "`echo $release | grep -iE 'release\s[67]'`" ]]; then
            config_centos_vagent_respawn
        elif [[ -n "`echo $release | grep -iE 'release\s5'`" ]]; then
            config_centos5_vagent_respawn
        fi
    elif [[ -n "`echo $issue | grep -i debian`" ]]; then
        if [[ -n "`echo $issue | grep -iE 'Linux\s[78]'`" ]]; then
            config_debian_vagent_respawn
        fi
    elif [[ -n "`echo $issue | grep -i ubuntu`" ]]; then
        if [[ -n "`echo $issue | grep -iE 'ubuntu'`" ]]; then
            config_ubuntu_vagent_respawn
        fi
    elif [[ -n "`echo $issue | grep -i SUSE`" ]]; then
        config_suse_vagent_respawn
    else
        log "Unknown or not supported system"
    fi
}

function install_lb_vagent() {
    directory=`pwd`
    cd /usr/local
    /usr/bin/wget http://$XENIP:20016/v1/static/lb_vagent.tar.gz >/dev/null 2>&1
    if [[ $? -ne 0 || ! -f "./lb_vagent.tar.gz" ]]; then
        log "Download lb_vagent.tar.gz error"
        exit 1
    fi
    tar xzf lb_vagent.tar.gz
    rm -f lb_vagent.tar.gz
    mv -f vagent/haproxy /etc/init.d/
    cpu_num=`grep "processor" /proc/cpuinfo | sort -u | wc -l`
    case $cpu_num in
        2)
            mv -f vagent/haproxy.cfg.2c /etc/haproxy/haproxy.cfg
            ;;
        4)
            mv -f vagent/haproxy.cfg.4c /etc/haproxy/haproxy.cfg
            ;;
        *)
            log "Get cpu_num error"
            exit 1
            ;;
    esac
    service haproxy restart
    cd $directory
    config_centos_vagent_respawn

    # monitor haproxy state
    sed -i "/haproxy_chk.sh/d" /etc/crontab
    echo "*/5 * * * * root /usr/local/vagent/haproxy_chk.sh > /dev/null 2>&1" >> /etc/crontab
    service crond restart
}

if [[ $# -eq 0 ]]; then
    parse_proc_cmdline
else
    parse_cmdline $@
fi
bind_ctrl_dev_to_eth6
config_passwd
change_ipaddr
if [[ ! -f "$LBCONF" ]]; then
    install_vagent
else
    install_lb_vagent
fi