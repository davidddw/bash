#!/bin/bash

# oss配置

#set -x

source `pwd`/config.sh
MT=/usr/local/bin/mt
SSHPASS='/usr/bin/sshpass'
SSH='/usr/bin/ssh'
SCP='/usr/bin/scp'
RM='/bin/rm'
SED='/bin/sed'
MYSQL='/usr/bin/mysql'
LOGFILE=/var/log/config_host.log

function setenable() 
{
    process=$1
    sed -i "s/$process = .*/$process = enable/" \
    /usr/local/livecloud/conf/livecloud.conf
}

function setdisable() 
{
    process=$1
    sed -i "s/$process = .*/$process = disable/" \
    /usr/local/livecloud/conf/livecloud.conf
}

log()
{
    echo -n $1 | tee -a $LOGFILE
}

function get_result() {
    local status=$?
    if [ $status -ne 0 ]; then
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
    else
        echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    fi
    return $status
}

function install_bss()
{
    cd $(dirname $1)
    HOMEDIR=$PWD/$(basename $1)
    cd $HOMEDIR
    sed -i -e "s/\(public_ip_address\ =\ \).*/\1$BSS_CONTROLLER/" \
-e "s/\(controller_control_ip\ =\ \).*/\1$BSS_PRIV/" \
-e "s/\(pxe_enabled\ =\ \).*/\1false/" $HOMEDIR/lc_startup.conf
    sed -i 's/mysql -uroot -p mysql </mysql </' $HOMEDIR/lc_startup.sh
    (echo y; echo bss; echo y; echo y) | $HOMEDIR/lc_startup.sh -i -c \
        $HOMEDIR/lc_startup.conf
    setenable httpd
    setenable nginx
    setenable charge
    setenable resourcejob
    setenable cashier
    setenable postman
    setdisable idagent
    setdisable keystone
    setdisable lcrmd
    setdisable vmdriver
    setdisable lcpd
    setdisable lcmond
    setdisable lcsnfd
    setdisable talker
    setdisable storekeeper
    setdisable vmwareadapter
    setdisable backup
    setdisable painter
    setdisable analyzer
    setdisable lcwebapi
    setdisable nodelistener
    setdisable sdncontroller
    setdisable azure
    sed -i -e "s/\(listen \)[0-9.]*\(:80;\)/\1$BSS_CONTROLLER\2/" \
-e "s/\(https:\/\/\)[0-9.]*\(\/;\)/\1$BSS_CONTROLLER\2/" \
/etc/nginx/conf.d/ssl.conf
    sed -i -e "s/\(charge\ =\ \).*/\1enable/" \
-e "s/\(local_public_ip\ =\ \).*/\1$BSS_CONTROLLER/" \
-e "s/\(mysql_master_ip\ =\ \).*/\1$BSS_CONTROLLER/" \
/usr/local/livecloud/conf/livecloud.conf
    (echo security421) | livecloud refresh
    cd -
}

function install_oss()
{
    cd $(dirname $1)
    HOMEDIR=$PWD/$(basename $1)
    cd $HOMEDIR
    sed -i -e "s/\(public_ip_address\ =\ \).*/\1$OSS_CONTROLLER/" \
-e "s/\(controller_control_ip\ =\ \).*/\1$OSS_PRIV/" \
-e "s/\(pxe_enabled\ =\ \).*/\1false/" $HOMEDIR/lc_startup.conf
    (echo y; echo oss ) | $HOMEDIR/lc_startup.sh -i -c $HOMEDIR/lc_startup.conf
    sed -i -e "s/\(local_public_ip\ =\ \).*/\1$OSS_CONTROLLER/" \
-e "s/\(local_ctrl_ip\ =\ \).*/\1$OSS_PRIV/" \
-e "s/\(mysql_master_ip\ =\ \).*/\1127.0.0.1/" \
-e "s/\(mongo_master_ip\ =\ \).*/\1$OSS_PRIV/" \
-e "s/\(domain.lcuuid\ =\ \).*/\1$OSS_DOMAIN_ID/" \
/usr/local/livecloud/conf/livecloud.conf
    setenable lcrmd
    setenable vmdriver
    setenable lcpd
    setenable lcmond
    setenable lcsnfd
    setenable postman
    setenable talker
    setenable storekeeper
    setenable backup
    setenable painter
    setenable analyzer
    setenable lcwebapi
    setenable nodelistener
    setenable httpd
    setenable nginx
    setenable sdncontroller
    
    setdisable cashier
    setdisable idagent
    setdisable resourcejob
    setdisable vmwareadapter
    setdisable charge
    setdisable keystone
    setdisable azure

    sed -i -e "s/\(listen \)[0-9.]*\(:80;\)/\1$OSS_CONTROLLER\2/" \
-e "s/\(server_name \).*/\1${OSS_CONTROLLER};/" \
-e "s/\(https:\/\/\)[0-9.]*\(\/;\)/\1$OSS_CONTROLLER\2/" \
/etc/nginx/conf.d/ssl.conf

    sed -i -e "s/\(uuid\ =\ \).*/\1$OSS_DOMAIN_ID/" \
-e "s/\(url\ =\ \).*/\1$OSS_CONTROLLER/" \
-e "s/\(bss.url\ =\ \).*/\1$BSS_CONTROLLER/" \
-e "s/\(bss.public_url\ =\ \).*/\1$BSS_CONTROLLER/" \
-e "s/\(bss.uuid\ =\ \).*/\1$BSS_DOMAIN_ID/" /var/www/lcweb/lcc/config.ini
    sed -i -e 's/pack.enable = .*/pack.enable = 0;/' \
/var/www/lcweb/lcc/config.ini
    (echo security421) | /bin/livecloud refresh
    cd -
}

function update_bss()
{
    cd $(dirname $1)
    HOMEDIR=$PWD/$(basename $1)
    cd $HOMEDIR
    sed -i -e "s/\(public_ip_address\ =\ \).*/\1$BSS_CONTROLLER/" \
-e "s/\(controller_control_ip\ =\ \).*/\1$BSS_PRIV/" \
-e "s/\(pxe_enabled\ =\ \).*/\1false/" $HOMEDIR/lc_startup.conf
    sed -i 's/mysql -uroot -p mysql </mysql </' $HOMEDIR/lc_startup.sh
    (echo y; echo bss; echo y; echo y) | $HOMEDIR/lc_startup.sh -i \
        -c $HOMEDIR/lc_startup.conf
    setenable httpd
    setenable nginx
    setenable charge
    setenable resourcejob
    setenable cashier
    setenable postman
    setdisable idagent
    setdisable keystone
    setdisable lcrmd
    setdisable vmdriver
    setdisable lcpd
    setdisable lcmond
    setdisable lcsnfd
    setdisable talker
    setdisable storekeeper
    setdisable vmwareadapter
    setdisable backup
    setdisable painter
    setdisable analyzer
    setdisable lcwebapi
    setdisable nodelistener
    setdisable sdncontroller
    setdisable azure
    sed -i -e "s/\(listen \)[0-9.]*\(:80;\)/\1$BSS_CONTROLLER\2/" \
-e "s/\(https:\/\/\)[0-9.]*\(\/;\)/\1$BSS_CONTROLLER\2/" \
/etc/nginx/conf.d/ssl.conf
    sed -i -e "s/\(charge\ =\ \).*/\1enable/" \
-e "s/\(local_public_ip\ =\ \).*/\1$BSS_CONTROLLER/" \
-e "s/\(mysql_master_ip\ =\ \).*/\1$BSS_CONTROLLER/" \
/usr/local/livecloud/conf/livecloud.conf
    /bin/livecloud start
    cd -
}

function update_oss()
{
    cd $(dirname $1)
    HOMEDIR=$PWD/$(basename $1)
    cd $HOMEDIR
    sed -i -e "s/\(public_ip_address\ =\ \).*/\1$OSS_CONTROLLER/" \
-e "s/\(controller_control_ip\ =\ \).*/\1$OSS_PRIV/" \
-e "s/\(pxe_enabled\ =\ \).*/\1false/" $HOMEDIR/lc_startup.conf
    (echo y; echo oss ) | $HOMEDIR/lc_startup.sh -i -c $HOMEDIR/lc_startup.conf
    sed -i -e "s/\(local_public_ip\ =\ \).*/\1$OSS_CONTROLLER/" \
-e "s/\(local_ctrl_ip\ =\ \).*/\1$OSS_PRIV/" \
-e "s/\(mysql_master_ip\ =\ \).*/\1127.0.0.1/" \
-e "s/\(mongo_master_ip\ =\ \).*/\1$OSS_PRIV/" \
-e "s/\(domain.lcuuid\ =\ \).*/\1$OSS_DOMAIN_ID/" \
/usr/local/livecloud/conf/livecloud.conf
    setenable lcrmd
    setenable vmdriver
    setenable lcpd
    setenable lcmond
    setenable lcsnfd
    setenable postman
    setenable talker
    setenable storekeeper
    setenable backup
    setenable painter
    setenable analyzer
    setenable lcwebapi
    setenable nodelistener
    setenable httpd
    setenable nginx
    setenable sdncontroller
    
    setdisable cashier
    setdisable idagent
    setdisable resourcejob
    setdisable vmwareadapter
    setdisable charge
    setdisable keystone
    setdisable azure

    sed -i -e "s/\(listen \)[0-9.]*\(:80;\)/\1$OSS_CONTROLLER\2/" \
-e "s/\(server_name \).*/\1${OSS_CONTROLLER};/" \
-e "s/\(https:\/\/\)[0-9.]*\(\/;\)/\1$OSS_CONTROLLER\2/" \
/etc/nginx/conf.d/ssl.conf

    sed -i -e "s/\(uuid\ =\ \).*/\1$OSS_DOMAIN_ID/" \
-e "s/\(url\ =\ \).*/\1$OSS_CONTROLLER/" \
-e "s/\(bss.url\ =\ \).*/\1$BSS_CONTROLLER/" \
-e "s/\(bss.public_url\ =\ \).*/\1$BSS_CONTROLLER/" \
-e "s/\(bss.uuid\ =\ \).*/\1$BSS_DOMAIN_ID/" /var/www/lcweb/lcc/config.ini
    sed -i -e 's/pack.enable = .*/pack.enable = 0;/' \
/var/www/lcweb/lcc/config.ini
    /bin/livecloud start
    cd -
}

bss_add_domain()
{
    log "Add domain ... "    
    str1="INSERT INTO \`domain\` VALUES (NULL,'"$OSS_DOMAIN"',
'"$OSS_CONTROLLER"','"$OSS_DOMAIN_ID"',2,'"$OSS_CONTROLLER"');"
    /usr/bin/mysql -D livecloud_bss -e "$str1"
    str1="INSERT INTO \`domain\` VALUES (NULL,'"$BSS_DOMAIN"',
'"$BSS_CONTROLLER"','"$BSS_DOMAIN_ID"',1,'"$BSS_CONTROLLER"');"
    /usr/bin/mysql -D livecloud_bss -e "$str1"
    get_result
}

oss_add_domain()
{
    log "Add domain ... "    
    str1="INSERT INTO \`domain_v2_2\` VALUES (NULL,'"$OSS_DOMAIN"',
'"$OSS_CONTROLLER"',2,'"$OSS_DOMAIN_ID"','"$OSS_CONTROLLER"');"
    /usr/bin/mysql -D livecloud -e "$str1" 
    str1="INSERT INTO \`domain_v2_2\` VALUES (NULL,'"$BSS_DOMAIN"',
'"$BSS_CONTROLLER"',1,'"$BSS_DOMAIN_ID"','"$BSS_CONTROLLER"');"
    /usr/bin/mysql -D livecloud -e "$str1" 

    str1="INSERT INTO \`domain_configuration_v2_2\` VALUES 
(NULL,'controller_ctrl_ip_min','','"$OSS_DOMAIN_ID"'),
(NULL,'controller_ctrl_ip_max','','"$OSS_DOMAIN_ID"'),
(NULL,'controller_ctrl_ip_netmask','','"$OSS_DOMAIN_ID"'),
(NULL,'vm_ctrl_ip_min','','"$OSS_DOMAIN_ID"'),
(NULL,'vm_ctrl_ip_max','','"$OSS_DOMAIN_ID"'),
(NULL,'vm_ctrl_ip_netmask','','"$OSS_DOMAIN_ID"'),
(NULL,'server_ctrl_ip_min','','"$OSS_DOMAIN_ID"'),
(NULL,'server_ctrl_ip_max','','"$OSS_DOMAIN_ID"'),
(NULL,'server_ctrl_ip_netmask','','"$OSS_DOMAIN_ID"'),
(NULL,'service_provider_ip_min','','"$OSS_DOMAIN_ID"'),
(NULL,'service_provider_ip_max','','"$OSS_DOMAIN_ID"'),
(NULL,'service_provider_ip_netmask','','"$OSS_DOMAIN_ID"'),
(NULL,'vm_service_ip_min','','"$OSS_DOMAIN_ID"'),
(NULL,'vm_service_ip_max','','"$OSS_DOMAIN_ID"'),
(NULL,'vm_service_ip_netmask','','"$OSS_DOMAIN_ID"'),
(NULL,'ctrl_plane_vlan','','"$OSS_DOMAIN_ID"'),
(NULL,'serv_plane_vlan','','"$OSS_DOMAIN_ID"'),
(NULL,'ctrl_plane_bandwidth','104857600','"$OSS_DOMAIN_ID"'),
(NULL,'serv_plane_bandwidth','104857600','"$OSS_DOMAIN_ID"'),
(NULL,'tunnel_protocol','VXLAN','"$OSS_DOMAIN_ID"');"
    /usr/bin/mysql -D livecloud -e "$str1"
    get_result
}

bss_add_user()
{
    log "Add User ... "
    str1="INSERT INTO \`user\` VALUES 
(null,1,'autotest','\$1\$pnJ4qnFW\$s/aPqss.82iaoW4WMVadh0','','',2,'','',
'autotest@yunshan.net.cn',NULL,'2015-01-01 00:15:38','','0',
'4+qaY41WMy1kU2ueCApNp06gtl1JPKTFPouOwPt1Lis=','',2000000,0.000000000,
'"$USER_UUID"');"
    /usr/bin/mysql -D livecloud_bss -e "$str1"
    get_result
}

oss_add_user()
{
    log "Add User ... "
    str1="INSERT INTO \`user_v2_2\` VALUES 
(null,'autotest','\$1\$pnJ4qnFW\$s/aPqss.82iaoW4WMVadh0',2,NULL,NULL,NULL,NULL,
NULL,NULL,NULL,NULL,'autotest@yunshan.net.cn',0,'"$USER_UUID"');"
    /usr/bin/mysql -D livecloud -e "$str1"
    str1="INSERT INTO \`fdb_user_v2_2\` VALUES
(null,1,'autotest','\$1\$pnJ4qnFW\$s/aPqss.82iaoW4WMVadh0','','',2,'','',
'autotest@yunshan.net.cn',NULL,'2015-01-01 00:15:38', '','0',
'4+qaY41WMy1kU2ueCApNp06gtl1JPKTFPouOwPt1Lis=','',2000000,0.000000000,
'"$USER_UUID"');"
    /usr/bin/mysql -D livecloud -e "$str1"
    get_result
}

bss_sync_db()
{
    log "Sync DB From OSS TO BSS ... "
    ${SSHPASS} -p ${OSS_PASS} ${SSH} root@${OSS_CONTROLLER} \
" mysql -e \"select lcuuid,name,type,charge_mode,state,price,content,plan_name,
product_type,domain from livecloud.product_specification_v2_2 where 
domain='${OSS_DOMAIN_ID}';\" > /tmp/db_tmp "
    ${SSHPASS} -p ${OSS_PASS} ${SCP} root@${OSS_CONTROLLER}:/tmp/db_tmp /tmp/ 
    ${SED} -i '1d' /tmp/db_tmp
    ${MYSQL} -e "load data infile '/tmp/db_tmp' into table 
livecloud_bss.product_specification character set utf8 fields terminated by 
'\t' lines terminated by '\n' (lcuuid,name,type,charge_mode,state,price,
content,plan_name,product_type,domain);"
    ${RM} -f /tmp/db_tmp
    ${SSHPASS} -p ${OSS_PASS} ${SSH} root@${OSS_CONTROLLER} \
        "/bin/rm -f /tmp/db_tmp"
    get_result
}

bss_mtps()
{
    log "Add pricing_plan ... "
    str1="INSERT INTO \`pricing_plan\` VALUES 
(NULL,'2C2G','vm','2C2G',
'{\"disk\": {\"size\": \"0\"}, \"cpu\": {\"num\": \"2\"}, \"memory\": {\"size\": \"2\"}}','{\"disk\": \"1\", \"cpu\": \"2\", \"memory\": \"2\"}',
'"$OSS_DOMAIN_ID"','never',0,NULL),
(NULL,'4C4G','vm','4C4G',
'{\"disk\": {\"size\": \"0\"}, \"cpu\": {\"num\": \"4\"}, \"memory\": {\"size\": \"4\"}}','{\"disk\": \"1\", \"cpu\": \"4\", \"memory\": \"4\"}',
'"$OSS_DOMAIN_ID"','never',0,NULL);"
    ${MYSQL} -D livecloud_bss -e "$str1"
    
    str1="INSERT INTO \`unit_price\` VALUES 
(NULL,'cpu','cpu','cpu','
{\"map\": [{\"domain\": \"(0, +Inf)\", \"b\": \"0\", \"k\": \"1\"}]}',
'per-day','"$OSS_DOMAIN_ID"'),
(NULL,'memory','memory','memory',
'{\"map\": [{\"domain\": \"(0, +Inf)\", \"b\": \"0\", \"k\": \"1\"}]}',
'per-day','"$OSS_DOMAIN_ID"'),
(NULL,'disk','disk','disk',
'{\"map\": [{\"domain\": \"[0, +Inf)\", \"b\": \"0\", \"k\": \"1\"}]}',
'per-day','"$OSS_DOMAIN_ID"'),
(NULL,'vgateway','vgw','vgateway',
'{\"map\": [{\"domain\": \"(0, +Inf)\", \"b\": \"0\", \"k\": \"1\"}]}',
'per-day','"$OSS_DOMAIN_ID"'),
(NULL,'valve','valve','valve',
'{\"map\": [{\"domain\": \"(0, +Inf)\", \"b\": \"0\", \"k\": \"1\"}]}',
'per-day','"$OSS_DOMAIN_ID"'),
(NULL,'lb','load-balancer','lb',
'{\"map\": [{\"domain\": \"(0, +Inf)\", \"b\": \"0\", \"k\": \"1\"}]}',
'per-day','"$OSS_DOMAIN_ID"'),
(NULL,'general_bandw','bandwidth','general_bandw',
'{\"map\": [{\"domain\": \"(0, +Inf)\", \"b\": \"0\", \"k\": \"1\"}]}',
'per-day','"$OSS_DOMAIN_ID"'),
(NULL,'mobile_bandw','bandwidth','mobile_bandw',
'{\"map\": [{\"domain\": \"(0, +Inf)\", \"b\": \"0\", \"k\": \"1\"}]}',
'per-day','"$OSS_DOMAIN_ID"'),
(NULL,'unicom_bandw','bandwidth','unicom_bandw',
'{\"map\": [{\"domain\": \"(0, +Inf)\", \"b\": \"0\", \"k\": \"1\"}]}',
'per-day','"$OSS_DOMAIN_ID"'),
(NULL,'mobile_ip','ip','mobile_ip',
'{\"map\": [{\"domain\": \"(0, +Inf)\", \"b\": \"0\", \"k\": \"1\"}]}',
'per-day','"$OSS_DOMAIN_ID"'),
(NULL,'unicom_ip','ip','unicom_ip',
'{\"map\": [{\"domain\": \"(0, +Inf)\", \"b\": \"0\", \"k\": \"1\"}]}',
'per-day','"$OSS_DOMAIN_ID"'),
(NULL,'cloud_disk','block-device','cloud_disk',
'{\"map\": [{\"domain\": \"[0, +Inf)\", \"b\": \"0\", \"k\": \"1\"}]}',
'per-day','"$OSS_DOMAIN_ID"'),
(NULL,'cloud_disk_snap','block-device-snapshot','cloud_disk_snap',
'{\"map\": [{\"domain\": \"[0, +Inf)\", \"b\": \"0\", \"k\": \"1\"}]}',
'per-day','"$OSS_DOMAIN_ID"'),
(NULL,'snapshot','vm-snapshot','snapshot',
'{\"map\": [{\"domain\": \"(0, +Inf)\", \"b\": \"0\", \"k\": \"1\"}]}',
'per-day','"$OSS_DOMAIN_ID"'),
(NULL,'VFW','vfw','VFW',
'{\"map\": [{\"domain\": \"[0, +Inf)\", \"b\": \"0\", \"k\": \"1.5\"}]}',
'per-day','"$OSS_DOMAIN_ID"');"  
    /usr/bin/mysql -D livecloud_bss -e "$str1"
    get_result
}

oss_mtps()
{
    log "Add Product Specification ... "
    str1="INSERT INTO \`product_specification_v2_2\` VALUES
(NULL,'`uuidgen`','虚拟网关',1,4,1,0.000000000,
'{\"description\": \"vgateway\", \"vgateway_info\": {\"wans\": 3, \"rate\": 1000, \"lans\": 3}}',
'vgateway',2,'"$OSS_DOMAIN_ID"'),
(NULL,'`uuidgen`','带宽共享器',1,4,1,0.000000000,
'{\"description\": \"valve\", \"valve_info\": {\"wans\": 3, \"ips\": 9, \"lans\": 1, \"bw_weight\": {\"1\":2, \"3\": 2, \"2\": 3, \"5\": 0, \"4\": 1, \"7\": 0, \"6\": 
0, \"8\": 0}}}',
'valve',17,'"$OSS_DOMAIN_ID"'),
(NULL,'`uuidgen`','负载均衡器',1,4,1,0.000000000,
'{\"user_disk_size\": 0, \"description\": \"lb\", \"compute_size\": {\"mem_size\": 2, \"vcpu_num\": 2,\"sys_disk_size\": 50}}',
'lb',9,'"$OSS_DOMAIN_ID"'),
(NULL,'`uuidgen`','通用带宽',1,4,1,0.000000000,
'{\"isp\": 0, \"description\": \"general_bandw\"}','general_bandw',5,'"$OSS_DOMAIN_ID"'),
(NULL,'`uuidgen`','移动带宽',1,4,1,0.000000000,
'{\"isp\": 1, \"description\": \"mobile_bandw\"}','mobile_bandw',5,'"$OSS_DOMAIN_ID"'),
(NULL,'`uuidgen`','联通带宽',1,4,1,0.000000000,
'{\"isp\": 2, \"description\": \"unicom_bandw\"}','unicom_bandw',5,'"$OSS_DOMAIN_ID"'),
(NULL,'`uuidgen`','移动IP',1,4,1,0.000000000,
'{\"isp\": 1, \"description\": \"mobile_ip\"}','mobile_ip',4,'"$OSS_DOMAIN_ID"'),
(NULL,'`uuidgen`','联通IP',1,4,1,0.000000000,
'{\"isp\": 2, \"description\": \"unicom_ip\"}','unicom_ip',4,'"$OSS_DOMAIN_ID"'),
(NULL,'`uuidgen`','4C4G',1,4,1,0.000000000,
'{\"user_disk_size\": 0, \"description\": \"4C4G\", \"compute_size\": {\"mem_size\": 4, \"vcpu_num\": 4,\"sys_disk_size\": 50}}',
'4C4G',1,'"$OSS_DOMAIN_ID"'),
(NULL,'`uuidgen`','2C2G',1,4,1,0.000000000,
'{\"user_disk_size\": 0, \"description\": \"2C2G\", \"compute_size\": {\"mem_size\": 2, \"vcpu_num\": 2,\"sys_disk_size\": 50}}',
'2C2G',1,'"$OSS_DOMAIN_ID"'),
(NULL,'`uuidgen`','VFW',1,4,1,0.000000000,
'{\"service_vendor\": \"TOPSEC\", \"user_disk_size\": 0, \"description\": \"VFW\", \"compute_size\": {\"mem_size\": 2, \"vcpu_num\": 2, \"sys_disk_size\": 50}}',
'VFW',16,'"$OSS_DOMAIN_ID"'),
(NULL,'`uuidgen`','云硬盘',2,4,1,0.000000000,
'{\"block_device_type\": 0, \"description\": \"cloud_disk\"}',
'cloud_disk',19, '"$OSS_DOMAIN_ID"'),
(NULL,'`uuidgen`','云硬盘快照',2,4,1,0.000000000,
'{\"block_device_type\": 0, \"description\": \"cloud_disk_snap\"}',
'cloud_disk_snap',20, '"$OSS_DOMAIN_ID"'),
(NULL,'`uuidgen`','虚拟机快照',2,4,1,0.000000000,
'{\"description\": \"snapshot\"}','snapshot',11,'"$OSS_DOMAIN_ID"');"
    /usr/bin/mysql -D livecloud -e "$str1"

    XEN_POOL=`mt pool.list | awk '/XenPool/{print $6}'`
    $MT pool.add-product-specification name=KVMPool \
        product_specification=4C4G >>$LOGFILE 2>&1 
    $MT pool.add-product-specification name=KVMPool \
        product_specification=2C2G >>$LOGFILE 2>&1 
    $MT pool.add-product-specification name=KVMPool \
        product_specification=lb >>$LOGFILE 2>&1 
    $MT pool.add-product-specification name=KVMPool \
        product_specification=VFW >>$LOGFILE 2>&1 
    get_result
}

bss_reload_cashier()
{
    kill -9 `ps -ef| grep cashier | grep -v "grep" | awk '{print $2}'`
    /usr/bin/python /usr/local/livecloud/bin/cashier/cashier.py -d
}

oss_add_base()
{
    log "Add cluster ... "
    $MT cluster.add name=regression domain=$OSS_DOMAIN >>$LOGFILE 2>&1 
    get_result

    log "Generate license ... "
    license=$($MT license.generate user_name=Yunshan rack_serial_num=1 \
server_num=10 lease=12 activation_time=`date +"%Y-%m-%d"`)
    $MT rack.add cluster_name=regression name=rack1 license=${license} \
switch_type=Ethernet >>$LOGFILE 2>&1 
    get_result

    log "Add rack ... "
    license=$($MT license.generate user_name=Yunshan rack_serial_num=2 \
server_num=10 lease=12 activation_time=`date +"%Y-%m-%d"`)
    $MT rack.add cluster_name=regression name=rack2 license=${license} \
switch_type=Ethernet >>$LOGFILE 2>&1 
    get_result

    log "Add vlantag-ranges ... "
    $MT vlantag-ranges.config rack_name=rack1 ranges=10-1000 >>$LOGFILE 2>&1 
    $MT vlantag-ranges.config rack_name=rack2 ranges=10-1000 >>$LOGFILE 2>&1 
    $MT vlantag-ranges.config type=ISP ranges=1-8 >>$LOGFILE 2>&1 
    get_result

    log "Add ip ranges ... "
    $MT ip-ranges.config type=SERVER_CTRL ip_min=${SERVER_CTRL_PRE}.0 \
        ip_max=${SERVER_CTRL_PRE}.255 netmask=16 domain=$OSS_DOMAIN \
        >>$LOGFILE 2>&1 
    $MT ip-ranges.config type=VM_CTRL ip_min=${VM_CTRL_PRE}.0 \
        ip_max=${VM_CTRL_PRE}.255 netmask=16 domain=$OSS_DOMAIN \
        >>$LOGFILE 2>&1 
    $MT ip-ranges.config type=VM_SERVICE ip_min=${VM_SERVICE_PRE}.0 \
        ip_max=${VM_SERVICE_PRE}.255 netmask=16 domain=$OSS_DOMAIN \
        >>$LOGFILE 2>&1 
    get_result
}

update_oss_host()
{
    cd /usr/local/livecloud/nsp
    IFS=, read -r -a RACK1_NSP_IPS <<< "$rack1_nsps"
    if [[ ${#RACK1_NSP_IPS[@]} -gt 0 ]]; then
        for host in ${RACK1_NSP_IPS[@]}; do
            /usr/local/livecloud/script/lc_devctl.sh config $host root \
                $PASSWD | tee -a $LOGFILE
        done
        (echo y; ) | /usr/local/livecloud/script/lc_devctl.sh \
            update nsp-livegate | tee -a $LOGFILE
        for host in ${RACK1_NSP_IPS[@]}; do
            /usr/local/livecloud/script/lc_devctl.sh config $host root \
                $PASSWD | tee -a $LOGFILE
        done
        (echo y; ) | /usr/local/livecloud/script/lc_devctl.sh \
            update kvm-nsp-dfi | tee -a $LOGFILE
        for host in ${RACK1_NSP_IPS[@]}; do
            /usr/local/livecloud/script/lc_devctl.sh config $host root \
                $PASSWD | tee -a $LOGFILE
        done
        (echo y; ) | /usr/local/livecloud/script/lc_devctl.sh \
            update kvm-nsp-dfi-ker | tee -a $LOGFILE
    fi
    IFS=, read -r -a RACK2_NSP_IPS <<< "$rack2_nsps"
    if [[ ${#RACK2_NSP_IPS[@]} -gt 0 ]]; then
        for host in ${RACK2_NSP_IPS[@]}; do
            /usr/local/livecloud/script/lc_devctl.sh config $host root \
                $PASSWD | tee -a $LOGFILE
        done
        (echo y; ) | /usr/local/livecloud/script/lc_devctl.sh \
            update nsp-livegate | tee -a $LOGFILE
        for host in ${RACK2_NSP_IPS[@]}; do
            /usr/local/livecloud/script/lc_devctl.sh config $host root \
                $PASSWD | tee -a $LOGFILE
        done
        (echo y; ) | /usr/local/livecloud/script/lc_devctl.sh \
            update kvm-nsp-dfi | tee -a $LOGFILE
        for host in ${RACK2_NSP_IPS[@]}; do
            /usr/local/livecloud/script/lc_devctl.sh config $host root \
                $PASSWD | tee -a $LOGFILE
        done
        (echo y; ) | /usr/local/livecloud/script/lc_devctl.sh \
            update kvm-nsp-dfi-ker | tee -a $LOGFILE
    fi
    cd -
    cd /usr/local/livecloud/kvm
    IFS=, read -r -a RACK1_KVM_IPS <<< "$rack1_kvms"
    if [[ ${#RACK1_KVM_IPS[@]} -gt 0 ]]; then
        for host in ${RACK1_KVM_IPS[@]}; do
            /usr/local/livecloud/script/lc_devctl.sh config $host root \
                $PASSWD | tee -a $LOGFILE
        done
        (echo y; ) | /usr/local/livecloud/script/lc_devctl.sh \
            update agent kvm | tee -a $LOGFILE
    fi
    IFS=, read -r -a RACK2_KVM_IPS <<< "$rack2_kvms"
    if [[ ${#RACK2_KVM_IPS[@]} -gt 0 ]]; then
        for host in ${RACK2_KVM_IPS[@]}; do
            /usr/local/livecloud/script/lc_devctl.sh config $host root \
                $PASSWD | tee -a $LOGFILE
        done
        (echo y; ) | /usr/local/livecloud/script/lc_devctl.sh \
            update agent kvm | tee -a $LOGFILE
    fi
    cd -
    cd /usr/local/livecloud/xen
    IFS=, read -r -a RACK1_XEN_IPS <<< "$rack1_xens"
    if [[ ${#RACK1_XEN_IPS[@]} -gt 0 ]]; then
        for host in ${RACK1_XEN_IPS[@]}; do
            /usr/local/livecloud/script/lc_devctl.sh config $host root \
                $PASSWD | tee -a $LOGFILE
        done
        (echo y; ) | /usr/local/livecloud/script/lc_devctl.sh \
            update agent xen | tee -a $LOGFILE
    fi
    IFS=, read -r -a RACK2_XEN_IPS <<< "$rack2_xens"
    if [[ ${#RACK2_XEN_IPS[@]} -gt 0 ]]; then
        for host in ${RACK2_XEN_IPS[@]}; do
            /usr/local/livecloud/script/lc_devctl.sh config $host root \
                $PASSWD | tee -a $LOGFILE
        done
        (echo y; ) | /usr/local/livecloud/script/lc_devctl.sh \
            update agent xen | tee -a $LOGFILE
    fi
    cd -
}

oss_add_host()
{
    IFS=, read -r -a RACK1_NSP_IPS <<< "$rack1_nsps"
    if [[ ${#RACK1_NSP_IPS[@]} -gt 0 ]]; then
        for host in ${RACK1_NSP_IPS[@]}; do
            log "Add gateway ${RACK1_NSP_IPS} ... "
            $MT host.add ip=${RACK1_NSP_IPS} type=NSP \
                uplink_ip="192.168.2.${RACK1_NSP_IPS##*.}" \
                uplink_netmask=16 uplink_gateway=192.168.0.1 user_name=root \
                user_passwd=$PASSWD rack_name=rack1 nic_type=Gigabit \
                >>$LOGFILE 2>&1
            get_result
        done
    fi
    IFS=, read -r -a RACK2_NSP_IPS <<< "$rack2_nsps"
    if [[ ${#RACK2_NSP_IPS[@]} -gt 0 ]]; then
        for host in ${RACK2_NSP_IPS[@]}; do
            log "Add gateway ${RACK2_NSP_IPS} ... "
            $MT host.add ip=${RACK2_NSP_IPS} type=NSP \
                uplink_ip="192.168.2.${RACK2_NSP_IPS##*.}" \
                uplink_netmask=16 uplink_gateway=192.168.0.1 user_name=root \
                user_passwd=$PASSWD rack_name=rack2 nic_type=Gigabit \
                >>$LOGFILE 2>&1
        get_result
        done
    fi
    IFS=, read -r -a RACK1_KVM_IPS <<< "$rack1_kvms"
    if [[ ${#RACK1_KVM_IPS[@]} -gt 0 ]]; then
        for host in ${RACK1_KVM_IPS[@]}; do
            log "Add kvm host $host ... "
            $MT host.add ip=$host type=VM user_name=root user_passwd=$PASSWD \
                rack_name=rack1 htype=KVM nic_type=Gigabit \
                storage_link_ip=$host >>$LOGFILE 2>&1
            get_result
        done
    fi 
    IFS=, read -r -a RACK2_KVM_IPS <<< "$rack2_kvms"
    if [[ ${#RACK2_KVM_IPS[@]} -gt 0 ]]; then
        for host in ${RACK2_KVM_IPS[@]}; do
            log "Add kvm host $host ... "
            $MT host.add ip=$host type=VM user_name=root user_passwd=$PASSWD \
                rack_name=rack2 htype=KVM nic_type=Gigabit \
                storage_link_ip=$host >>$LOGFILE 2>&1
            get_result
        done
    fi
    IFS=, read -r -a RACK1_XEN_IPS <<< "$rack1_xens"
    if [[ ${#RACK1_XEN_IPS[@]} -gt 0 ]]; then
        for host in ${RACK1_XEN_IPS[@]}; do
            log "Add xen host $host ... "
            $MT host.add ip=$host type=VM user_name=root user_passwd=$PASSWD \
                rack_name=rack1 htype=Xen nic_type=Gigabit >>$LOGFILE 2>&1
            get_result
        done
    fi
    IFS=, read -r -a RACK2_XEN_IPS <<< "$rack2_xens"
    if [[ ${#RACK2_XEN_IPS[@]} -gt 0 ]]; then
        for host in ${RACK2_XEN_IPS[@]}; do
            log "Add xen host $host ... "
            $MT host.add ip=$host type=VM user_name=root user_passwd=$PASSWD \
                rack_name=rack2 htype=Xen nic_type=Gigabit >>$LOGFILE 2>&1
            get_result
        done
    fi
    log "Add NSP pool ... "
    $MT pool.add name=NSPPool type=NSP cluster_name=regression >>$LOGFILE 2>&1
    get_result
    log "Add KVM pool ... "
    $MT pool.add name=KVMPool type=VM cluster_name=regression ctype=KVM \
        stype=local >>$LOGFILE 2>&1
    get_result
    log "Add XEN pool ... "
    $MT pool.add name=XenPool type=VM cluster_name=regression ctype=Xen \
        stype=local >>$LOGFILE 2>&1
    get_result
    IFS=, read -r -a RACK1_NSP_IPS <<< "$rack1_nsps"
    if [[ ${#RACK1_NSP_IPS[@]} -gt 0 ]]; then
        for host in ${RACK1_NSP_IPS[@]}; do
            log "NSP Host ${RACK1_NSP_IPS} join ... "
            $MT host.join ip=${RACK1_NSP_IPS} name=nsp${RACK1_NSP_IPS##*.} \
                pool_name=NSPPool >>$LOGFILE 2>&1
            get_result
        done
    fi
    IFS=, read -r -a RACK2_NSP_IPS <<< "$rack2_nsps"
    if [[ ${#RACK2_NSP_IPS[@]} -gt 0 ]]; then
        for host in ${RACK2_NSP_IPS[@]}; do
            log "NSP Host ${RACK2_NSP_IPS} join ... "
            $MT host.join ip=${RACK2_NSP_IPS} name=nsp${RACK2_NSP_IPS##*.} \
                pool_name=NSPPool >>$LOGFILE 2>&1
            get_result
        done
    fi
    IFS=, read -r -a RACK1_KVM_IPS <<< "$rack1_kvms"
    if [[ ${#RACK1_KVM_IPS[@]} -gt 0 ]]; then
        for host in ${RACK1_KVM_IPS[@]}; do
            log "KVM Host $host join ... "
            $MT host.join pool_name=KVMPool ip=$host name=centos${host##*.} \
                >>$LOGFILE 2>&1
            get_result
        done
    fi
    IFS=, read -r -a RACK2_KVM_IPS <<< "$rack2_kvms"
    if [[ ${#RACK2_KVM_IPS[@]} -gt 0 ]]; then
        for host in ${RACK2_KVM_IPS[@]}; do
            log "KVM Host $host join ... "
            $MT host.join pool_name=KVMPool ip=$host name=centos${host##*.} \
                >>$LOGFILE 2>&1
            get_result
        done
    fi
    IFS=, read -r -a RACK1_XEN_IPS <<< "$rack1_xens"
    if [[ ${#RACK1_XEN_IPS[@]} -gt 0 ]]; then
        for host in ${RACK1_XEN_IPS[@]}; do
            log "XEN Host $host join ... "
            $MT host.join pool_name=XenPool ip=$host name=xenserver${host##*.} \
                >>$LOGFILE 2>&1
            get_result
        done
    fi
    IFS=, read -r -a RACK2_XEN_IPS <<< "$rack2_xens"
    if [[ ${#RACK2_XEN_IPS[@]} -gt 0 ]]; then
        for host in ${RACK2_XEN_IPS[@]}; do
            log "XEN Host $host join ... "
            $MT host.join pool_name=XenPool ip=$host name=xenserver${host##*.} \
                >>$LOGFILE 2>&1
            get_result
        done
    fi
    # mt host.join ip=${gateway} name=nsp${gateway##*.} pool_name=NSPPool
    # mt host.peer-join ip1=172.16.1.111 ip2=172.16.1.112 name=xen pool_name=XenPool
}

oss_add_IP_template()
{
    log "Add ISP ... "
    $MT isp.config domain=$OSS_DOMAIN ISP=1 name=Mobile >>$LOGFILE 2>&1
    $MT isp.config domain=$OSS_DOMAIN ISP=2 name=Unicom >>$LOGFILE 2>&1
    get_result
    
    log "Add IPS ... "
    for i in `seq 161 200`; do
        $MT ip.add ip=$ISP1_PREFIX.$i netmask=16 gateway=$ISP1_GATEWAY ISP=1 \
            product_specification=mobile_ip vlantag=1 domain=$OSS_DOMAIN \
            >>$LOGFILE 2>&1
    done
    for i in `seq 161 200`; do
        $MT ip.add ip=$ISP2_PREFIX.$i netmask=16 gateway=$ISP2_GATEWAY ISP=2 \
            product_specification=unicom_ip vlantag=4 domain=$OSS_DOMAIN \
            >>$LOGFILE 2>&1
    done
    get_result
    
    log "Add CentOS Temlate ... "
    $MT template.config name=centos6.5 ttype=VM domain=$OSS_DOMAIN \
        vendor=YUNSHAN >>$LOGFILE 2>&1
    $MT template.config name=centos7.0 ttype=VM domain=$OSS_DOMAIN \
        vendor=YUNSHAN >>$LOGFILE 2>&1
    $MT template.config name=centos6.6-gui ttype=VM domain=$OSS_DOMAIN \
        vendor=YUNSHAN >>$LOGFILE 2>&1
    get_result
    log "Add Ubuntu Temlate ... "
    $MT template.config name=ubuntu12.04 ttype=VM domain=$OSS_DOMAIN \
        vendor=YUNSHAN >>$LOGFILE 2>&1
    $MT template.config name=ubuntu14.04 ttype=VM domain=$OSS_DOMAIN \
        vendor=YUNSHAN >>$LOGFILE 2>&1
    $MT template.config name=debian8.2 ttype=VM domain=$OSS_DOMAIN \
        vendor=YUNSHAN >>$LOGFILE 2>&1
    get_result
    log "Add LB Temlate ... "
    $MT template.config name=centos6.5-lb ttype=LoadBalancer \
        domain=$OSS_DOMAIN vendor=YUNSHAN >>$LOGFILE 2>&1
    get_result
    log "Add Windows Temlate ... "
    $MT template.config name=_01_Windows2008CN_02_64Bit_05_CnEnterprise \
        ttype=VM domain=$OSS_DOMAIN vendor=YUNSHAN >>$LOGFILE 2>&1
    $MT template.config name=_01_Windows2012CN_02_64Bit_05_CnEnterprise \
        ttype=VM domain=$OSS_DOMAIN vendor=YUNSHAN >>$LOGFILE 2>&1
    get_result
    log "Add VFW Temlate ... "
    $MT template.config name=template-Topsec-vfw-4.0-new ttype=Firewall \
        domain=$OSS_DOMAIN vendor=TOPSEC >>$LOGFILE 2>&1
    get_result
    
    log "Active pool ... "
    $MT storage.list | awk '/SR_Local/{cmd="mt storage.activate id="$1" host="$7;system(cmd)}' >>$LOGFILE 2>&1
    get_result

    log "KVM Storage add ... "
    if [[ -n "$rack2_kvms" ]]; then
        host_list=$rack1_kvms,$rack2_kvms
    else
        host_list=$rack1_kvms
    fi
    $MT storage.add backend=ceph-rbd domain=$OSS_DOMAIN name=capacity \
        type=CAPACITY host=$host_list >>$LOGFILE 2>&1
    #$MT storage.add backend=ceph-rbd domain=$OSS_DOMAIN name=performance \
    #   type=CAPACITY host=$host_list
    get_result
}

oss_reload_talker()
{
    /bin/livecloud stop
    pid=`ps -ef| grep talker | grep -v "grep" | awk '{print $2}'`
    if [[ -n $pid ]]; then
        echo $pid
        kill -9 $pid
    fi
    /bin/livecloud start
}

if [ $# = 0 ]; then
    echo "Usage: "
    echo "       deploy install_bss <lc_release_xxxx>"
    echo "       deploy install_oss <lc_release_xxxx>"
    echo "       deploy update_bss  <lc_release_xxxx>" 
    echo "       deploy update_oss  <lc_release_xxxx>"
    echo "       deploy update_oss_host"
    echo "       deploy config_bss"
    echo "       deploy config_oss"
    echo "       deploy bss_sync_db"
    exit 0
fi

if [[ "$1" = "install_bss" ]]; then
    install_bss $2
fi
if [[ "$1" = "install_oss" ]]; then
    install_oss $2
fi
if [[ "$1" = "update_bss" ]]; then
    update_bss $2
fi
if [[ "$1" = "update_oss" ]]; then
    update_oss $2
fi
if [[ "$1" = "bss_sync_db" ]]; then
    bss_sync_db
    oss_reload_talker
fi
if [[ "$1" = "update_oss_host" ]]; then
    update_oss_host $2
fi
if [[ "$1" = "config_bss" ]]; then
    bss_add_domain
    bss_add_user
    bss_mtps
    bss_reload_cashier
fi
if [[ "$1" = "config_oss" ]]; then
    oss_add_domain
    oss_add_user
    oss_add_base
    oss_add_host
    oss_mtps
    oss_add_IP_template
    oss_reload_talker
fi

echo "Done"
exit 0