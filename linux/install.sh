#!/bin/sh

HYPERVISOR_PACKS="xen_pack.tar.gz pyagexec.tar.gz livegate_pack.tar.gz dfi_agent_pack.tar.gz dfi_agent_nsp_pack.tar.gz kvm_pack.tar.gz"
INSTALL_LOG=/tmp/livecloud_install.log
SCRIPTDIR='/usr/local/livecloud/script'

sqlusername="root"
sqlpassword="security421"

lcbackupdir="/root/for_backup_controller"
lcsys="/usr/local/livecloud"
lcweb="/var/www/lcweb"
lcweb_bss="/var/www/lcweb_bss"
lclog="/var/log"
lcforxen="$lcsys/xen"
lcforkvm="$lcsys/kvm"
lcfornsp="$lcsys/nsp"
lckernel="$lcsys/bin"
lcscript="$lcsys/script"
lchascript="$lcsys/script/ha"
lcdmscript="$lcsys/script/diskmgmt"
lcconfig="$lcsys/conf"
lclib="$lcsys/lib"
lcazureps="$lcsys/azure_publishsettings"

LC_BIN_DIR="/usr/local/livecloud/bin"

domain_name=2cloud.com
public_ip_address_bss=10.33.37.51
public_ip_address_oss=10.33.37.52
controller_control_interface=eth0
controller_control_ip=172.16.37.51


# **********************************
check_cmd_format() {
    typeset operator count check host passwd
    operator=$1
    shift
    if [ $# -eq 0 ]; then
        return 0
    fi
    if [ $# -eq 1 ] && [ $1 = ? ]; then
        show_cmd_help $operator
        exit 0
    fi
    count=0
    case $operator in
    download)
        if [ $# -gt 10 ]; then
            show_cmd_help $operator over
            exit 1
        fi
        while [ $# -ne 0 ]; do
            case $1 in
            -b | --branch)
                count=`expr $count + 00001`
                ;;
            -t | --tag)
                count=`expr $count + 00010`
                ;;
            -m | --module)
                count=`expr $count + 00100`
                ;;
            -p | --path)
                count=`expr $count + 01000`
                ;;
            -u | --user)
                count=`expr $count + 10000`
                ;;
            *)
                show_cmd_help $operator err
                exit 1
                ;;
            esac
            if [ $# -eq 1 ]; then
                show_cmd_help $operator miss
                exit 1
            fi
            shift 2
        done
        check=`echo $count | grep -w "[0-1]\{1,5\}"`
        if [ -z "$check" ]; then
            show_cmd_help $operator dup
            exit 1
        fi
        ;;
    enforce)
        case $1 in
        -l | --local)
            if [ $# -lt 2 ]; then
                show_cmd_help $operator miss
                exit 1
            fi
            if [ $# -gt 2 ]; then
                show_cmd_help $operator over
                exit 1
            fi
            ;;
        *)
            show_cmd_help $operator err
            exit 1
            ;;
        esac
        ;;
    autoset)
        if [ $# -gt 6 ]; then
            show_cmd_help $operator over
            exit 1
        fi
        while [ $# -ne 0 ]; do
            case $1 in
            -b | --branch)
                count=`expr $count + 001`
                ;;
            -t | --tag)
                count=`expr $count + 010`
                ;;
            -p | --path)
                count=`expr $count + 100`
                ;;
            *)
                show_cmd_help $operator err
                exit 1
                ;;
            esac
            if [ $# -eq 1 ]; then
                show_cmd_help $operator miss
                exit 1
            fi
            shift 2
        done
        check=`echo $count | grep -w "[0-1]\{1,3\}"`
        if [ -z "$check" ]; then
            show_cmd_help $operator dup
            exit 1
        fi
        ;;
    sys_release)
        if [ $# -gt 10 ]; then
            show_cmd_help $operator over
            exit 1
        fi
        while [ $# -ne 0 ]; do
            case $1 in
            -b | --branch)
                count=`expr $count + 0001`
                ;;
            -t | --tag)
                count=`expr $count + 0010`
                ;;
            -p | --path)
                count=`expr $count + 0100`
                ;;
            -l | --local)
                count=`expr $count + 1000`
                ;;
            -H | --host)
                hostlist=(`echo $2| tr "," " "`)
                ;;
            -P | --passwd)
                passwd=$2
                ;;
            *)
                show_cmd_help $operator err
                exit 1
                ;;
            esac
            if [ $# -eq 1 ]; then
                show_cmd_help $operator miss
                exit 1
            fi
            shift 2
        done
        check=`echo $count | grep -w "1[0-1]11\|1[0-1]10\|1[0-1]01"`
        if [ -n "$check" ]; then
            show_cmd_help $operator err
            exit 1
        fi
        check=`echo $count | grep -w "[0-1]\{1,3\}\|1[0-1]00"`
        if [ -z "$check" ]; then
            show_cmd_help $operator dup
            exit 1
        fi
        if [ -n "$hostlist" ] || [ -n "$passwd" ]; then
            if [ -z "$hostlist" ] || [ -z "$passwd" ]; then
                show_cmd_help $operator miss
                exit 1
            else
                for host in ${hostlist[@]}; do
                    check=`echo $host | grep -o \
                    "^\(\([0-9]\{1,2\}\|1[0-9]\{2\}\|2[0-4][0-9]\|25[0-5]\)\.\)\{3\}\([0-9]\{1,2\}\|1[0-9]\{2\}\|2[0-4][0-9]\|25[0-5]\)$"`
                    if [ "$check" != $host ]; then
                        show_cmd_help $operator err
                        exit 1
                    fi
                    check=`echo $host | grep -o "\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}" | \
                    xargs -I {} ping -i 0.2 -w 1 {} | grep -c -o "[^0-9][0-9]\{1,2\}% packet loss"`
                    if [ "$check" = "0" ]; then
                        show_cmd_help $operator err
                        exit 1
                    fi
                done
            fi
        fi
        ;;
    sys_install | self_update)
        show_cmd_help $operator over
        exit 1
        ;;
    sys_check)
        case $1 in
        -m | --module)
            if [ $# -lt 2 ]; then
                show_cmd_help $operator miss
                exit 1
            fi
            if [ $# -gt 2 ]; then
                show_cmd_help $operator over
                exit 1
            fi
            ;;
        *)
            show_cmd_help $operator err
            exit 1
            ;;
        esac
        ;;
    set_tag)
        if [ $# -lt 8 ]; then
            show_cmd_help $operator miss
            exit 1
        fi
        if [ $# -gt 10 ]; then
            show_cmd_help $operator over
            exit 1
        fi
        while [ $# -ne 0 ]; do
            case $1 in
            -A | --annotate)
                count=`expr $count + 00001`
                ;;
            -m | --module)
                count=`expr $count + 00010`
                ;;
            -b | --branch)
                count=`expr $count + 00100`
                ;;
            -t | --tag)
                count=`expr $count + 01000`
                ;;
            -u | --user)
                count=`expr $count + 10000`
                ;;
            *)
                show_cmd_help $operator err
                exit 1
                ;;
            esac
            if [ $# -eq 1 ]; then
                show_cmd_help $operator miss
                exit 1
            fi
            shift 2
        done
        check=`echo $count | grep -w "1\|11\|1[0-1]1\|10[0-1]1\|1[0-1]01\|110[0-1]1\|11[0-1]01"`
        if [ -n "$check" ]; then
            show_cmd_help $operator err
            exit 1
        fi
        check=`echo $count | grep -w "1111[0-1]"`
        if [ -z "$check" ]; then
            show_cmd_help $operator dup
            exit 1
        fi
        ;;
    esac
    return 0
}

# **********************************
check_sys_os () {
    typeset check
    echo -n "Checking operating system ... "
    check=`cat /etc/redhat-release | grep -o "CentOS"`
    if [ -z "$check" ]; then
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
        echo "ERROR ($command): CentOS is not detected"
        return 1
    fi
    check=`cat /etc/redhat-release | grep -o "7"`
    if [ -z "$check" ]; then
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
        echo "ERROR ($command): CentOS release 7 is not detected"
        return 1
    fi
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    return 0
}

check_sys_network () {
    typeset check
    echo -n "Checking network ... "
    check=`find /etc/sysconfig/network-scripts/ -name "ifcfg-[a-z][a-z]*[0-9]" |
    xargs grep -l "IPADDR=\"*\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}\"*"`
    if [ -z "$check" ]; then
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
        echo "ERROR ($command): Static ip is not detected"
        return 1
    fi
    check=`echo $check | grep -o "[a-z][a-z]*[0-9]" | xargs -I {} ethtool {} |
    grep -o "Link detected: yes"`
    if [ -z "$check" ]; then
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
        echo "ERROR ($command): Physical link is not detected"
        return 1
    fi
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    return 0
}

check_sys_mysql() {
    typeset check
    echo -n "Checking mysql ... "
    check=`mysql -V | grep -o "mysql  Ver 15\.1"`
    if [ -z "$check" ]; then
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
        echo "ERROR ($command): Mysql 14.14 is not detected"
        return 1
    fi
    check=`mysql -u$sqlusername -p$sqlpassword livecloud -e "show tables" | grep "ERROR"`
    if [ -n "$check" ]; then
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
        echo "ERROR ($command): Livecloud db is not detected"
        return 1
    fi
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    return 0
}

check_sys_apache () {
    typeset check
    echo -n "Checking apache ... "
    check=`apachectl -v | grep -o "Apache/2\.4\.6"`
    if [ -z "$check" ]; then
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
        echo "ERROR ($command): Apache 2.4.6 is not detected"
        return 1
    fi
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    return 0
}

check_sys_php () {
    typeset check
    echo -n "Checking php ... "
    check=`php -v | grep -o "PHP 7\.0\.5"`
    if [ -z "$check" ]; then
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
        echo "ERROR ($command): Php 7.0.5 is not detected"
        return 1
    fi
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    return 0
}

check_sys_mysql_python () {
    typeset check
    echo -n "Checking MYSQL-python ... "
    if [ ! -d /usr/lib/python*/site-packages/pymysql ]; then
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
        echo "ERROR ($command): python-PyMYSQL is not detected"
        return 1
    fi
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    return 0
}

__sys_check() {
    check_cmd_format sys_check $@
    case $2 in
    os | network | mysql | apache | php | mysql_python)
        check_sys_$2
        ;;
    *)
        check_sys_os
        check_sys_network
        check_sys_mysql
        check_sys_apache
        check_sys_php
        check_sys_mysql_python
        ;;
    esac
    return 0
}

# path="`pwd`/lc_release"
install_lcwebapi () {
    #copy state sniffer programs to /usr/local/livecloud/bin
    check=`ps aux | grep "node app.js" | grep -v "grep"`
    diffpid=`echo $check | cut -d " " -f2`
    if [ -n "$diffpid" ]; then
        kill -9 $diffpid
    fi
    sleep 1
    rm -rf $LC_BIN_DIR/lcwebapi
    mkdir -p $LC_BIN_DIR
    cp -rf $1/lcwebapi $LC_BIN_DIR
}

# install_adapter yynwadapter $path
install_adapter () {
    typeset adapter xpath
    adapter=$1
    xpath=$2

    #copy adapter to /usr/local/livecloud/bin
    check=`ps aux | grep $adapter | grep -v "grep"`
    diffpid=`echo $check | cut -d " " -f2`
    if [ -n "$diffpid" ]; then
        kill -9 $diffpid
    fi
    sleep 1
    rm -rf $LC_BIN_DIR/$adapter
    mkdir -p $LC_BIN_DIR
    cp -rf $xpath/$adapter $LC_BIN_DIR
}

# install_webpages $path
install_webpages () {
    typeset conf check
    echo -n "Configuring selinux ... "
    setenforce 0 &>> $INSTALL_LOG
    sed -i 's/^SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'

    echo -n "Configuring lcweb ... "
    rm -rf $lcweb > /dev/null 2>&1
    mkdir -p $lcweb > /dev/null
    cp -rf $1/lcweb /var/www > /dev/null
    mkdir -p $lcweb/public/plugin > /dev/null
    cp -rf $1/3parties/noVNC $lcweb/public/plugin > /dev/null
    cp -rf $1/3parties/Zend /var/www > /dev/null
    cp -rf $1/lcweb/lcwebinit/php/php.d /etc > /dev/null
    #cp -rf $1/lcweb/lcwebinit/php/lib/modules /usr/lib/php > /dev/null
    sed -i "/^\s*Listen/d" /etc/httpd/conf/httpd.conf
    sed -i "/SSLCertificateFile/d" /etc/httpd/conf/httpd.conf
    sed -i "/SSLCertificateKeyFile/d" /etc/httpd/conf/httpd.conf
    echo "Listen 127.0.0.1:80" >> /etc/httpd/conf/httpd.conf
    tmpdir=`pwd`
    cd /etc/httpd/conf/
    openssl genrsa -rand yunshan.net.cn -out server.pem 2048 &>> $INSTALL_LOG
    openssl req -new -batch -key server.pem -out server.csr &>> $INSTALL_LOG
    openssl x509 -req -days 365 -in server.csr -signkey server.pem -out server.crt &>> $INSTALL_LOG
    cd $tmpdir
    
    conf="/etc/httpd/conf/httpd.conf"
    check=`grep -o "^Timeout 6000$" $conf`
    if [ -z "$check" ]; then
        sed -i "s/^Timeout 60$/Timeout 6000/" $conf > /dev/null
    fi
    check=`grep -o "^DocumentRoot \"\/var\/www\/lcweb\"$" $conf`
    if [ -z "$check" ]; then
        sed -i "s/^DocumentRoot \"\/var\/www\/html\"$/DocumentRoot \"\/var\/www\/lcweb\"/" $conf > /dev/null
    fi
    check=`grep -o "^<Directory \/var\/www\/lcweb>$" $conf`
    if [ -z "$check" ]; then
        sed -i "/^# Note that from this point forward you must specifically allow$\
/i\<Directory \/var\/www\/lcweb>\n\
    Options Indexes FollowSymLinks Multiviews\n\
    AllowOverride All\n\
    Order allow,deny\n\
    Allow from all\n\
<\/Directory>\n\n#" $conf > /dev/null
    fi
    check=`grep -o "^DirectoryIndex index.html index.html.var index.php$" $conf`
    if [ -z "$check" ]; then
        sed -i "s/^DirectoryIndex index.html index.html.var$/& index.php/" $conf > /dev/null
    fi
    check=`grep -o "^AddType application\/x-httpd-php-source .phps$" $conf`
    if [ -z "$check" ]; then
        sed -i "/^AddType application\/x-gzip .gz .tgz$\
/a\AddType application\/x-httpd-php-source .phps" $conf > /dev/null
        sed -i "/^AddType application\/x-gzip .gz .tgz$\
/a\AddType application\/x-httpd-php .php" $conf > /dev/null
        sed -i "/^AddType application\/x-gzip .gz .tgz$\
/a\\" $conf > /dev/null
    fi
    
    cat << EOF > /etc/httpd/conf.d/ssl-oss.conf 
Listen 127.0.0.1:8080
<VirtualHost 127.0.0.1:8080>
    ServerName oss.dev4-2.com
    DocumentRoot /var/www/lcweb
    ErrorLog logs/oss_error.log
    CustomLog logs/oss_access_log common
    <Directory /var/www/lcweb>
        Options Indexes FollowSymLinks Multiviews
        AllowOverride All
        Order allow,deny
        Allow from all
    </Directory>
</VirtualHost>
EOF
    chmod 777 /var/www/lcweb/public/pdf/*
    chmod 777 /var/www/lcweb/public/images/tree/tree.png
    mkdir -p '/var/www/lcweb/public/report/'
    chmod 777 /var/www/lcweb/public/report
    chmod 777 /var/www/lcweb/public/report_template
    touch /var/log/lcweb.log
    chmod 777 /var/log/lcweb.log
    mkdir -p '/var/www/lcweb/public/images/upload/'
    chmod 777 /var/www/lcweb/public/images/upload/
    mkdir -p /var/www/lcweb_cache
    chmod 777 /var/www/lcweb_cache
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'

    echo -n "Configuring lcweb_bss ... "
    rm -rf $lcweb_bss > /dev/null 2>&1
    mkdir -p $lcweb_bss > /dev/null
    cp -rf $1/lcweb_bss /var/www > /dev/null
    mkdir -p $lcweb_bss/public/plugin > /dev/null
    cp -rf $1/3parties/noVNC $lcweb_bss/public/plugin > /dev/null
    mkdir -p /var/lib/php/bsssession > /dev/null
    chmod 770 /var/lib/php/bsssession
    chgrp apache /var/lib/php/bsssession
    sed -i "/^session.save_path = \"\/var\/lib\/php\/session\"/d" /etc/php.ini
    cat << EOF > /etc/httpd/conf.d/ssl-bss.conf 
<VirtualHost 127.0.0.1:80>
    ServerName bss.dev4-2.com
    DocumentRoot /var/www/lcweb_bss
    ErrorLog logs/bss_error.log
    CustomLog logs/bss_access_log common
    <Directory /var/www/lcweb_bss>
        Options Indexes FollowSymLinks Multiviews
        AllowOverride All
        Order allow,deny
        Allow from all
    </Directory>
</VirtualHost>
EOF
    chmod 777 /var/www/lcweb_bss/public/pdf/*
    mkdir -p '/var/www/lcweb_bss/public/report/'
    chmod 777 /var/www/lcweb_bss/public/report
    chmod 777 /var/www/lcweb_bss/public/report_template
    touch /var/log/lcweb.log
    chmod 777 /var/log/lcweb.log
    mkdir -p '/var/www/lcweb_bss/public/images/upload/'
    chmod 777 /var/www/lcweb_bss/public/images/upload/
    mkdir -p /var/www/lcweb_cache
    chmod 777 /var/www/lcweb_cache
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'

    echo -n "Configuring http ... "
    if [ -f /etc/httpd/nginx.conf ]; then
        mv -f /etc/httpd/nginx.conf /etc/httpd/nginx.conf.bak
    fi
    if [ -f /etc/httpd/conf.d/ssl.conf ]; then
        mv -f /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/ssl.conf.bak
    fi
    rm -f /etc/nginx/conf.d/*
    cp /var/www/lcweb/lcwebinit/nginx/ssl.conf /etc/nginx/conf.d/ssl-oss.conf
    cp /var/www/lcweb/lcwebinit/nginx/nginx.conf /etc/nginx/
    cp /var/www/lcweb_bss/lcwebinit/nginx/ssl.conf /etc/nginx/conf.d/ssl-bss.conf
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'

    echo -n "Configuring lcweb report schedule ... "
    sed -i "/buildreportform/d" /etc/crontab
    echo '10 0 * * 1 root curl "http://127.0.0.1/report/buildreportform?type=weekly" > /dev/null 2>&1' >>/etc/crontab
    echo '30 0 1 * * root curl "http://127.0.0.1/report/buildreportform?type=monthly" > /dev/null 2>&1' >>/etc/crontab
	systemctl enable httpd &>> $INSTALL_LOG
	systemctl restart httpd &>> $INSTALL_LOG
    if [[ $? -eq 0 ]]; then
        echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    else
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
    fi
    return 0
}

install_programs () {
    echo -n "Configuring lc_platform ... "
    mkdir -p $lcscript > /dev/null
    mkdir -p $lcscript/lc > /dev/null
    mkdir -p $lcscript/issu > /dev/null
    mkdir -p $lcscript/debug > /dev/null
    mkdir -p $lchascript > /dev/null
    mkdir -p $lcdmscript > /dev/null
    mkdir -p $lcconfig > /dev/null
    mkdir -p $lckernel > /dev/null
    mkdir -p $lcforxen > /dev/null
    mkdir -p $lcforkvm > /dev/null
    mkdir -p $lcfornsp > /dev/null
    mkdir -p $lclib > /dev/null
    mkdir -p $lcazureps > /dev/null
    pkill healthcheck > /dev/null
    pkill java > /dev/null
    pkill lcrmd > /dev/null
    pkill vmdriver > /dev/null
    pkill lcpd > /dev/null
    pkill lcmond > /dev/null
    pkill lcsnfd > /dev/null
    pkill postman.py > /dev/null
    pkill cashier.py > /dev/null
    pkill idagent.py > /dev/null
    pkill talker.py > /dev/null
    pkill storekeeper.py > /dev/null
    pkill cashier.py > /dev/null
    pkill backup.py > /dev/null
    pkill painter.py > /dev/null
    pkill sdncontroller.py > /dev/null
    pkill analyzer.py > /dev/null
    pkill exchange.py > /dev/null
    pkill neutronadapter.py > /dev/null

    rpm -Uvh --force $1/lc_program/lc_java/*.rpm &>> $INSTALL_LOG
    if [[ $? -eq 0 ]]; then
        echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    else
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
    fi

	echo -n "Install lc_program ..."
    if [ -e $1/lc_program/ovs-xs1.6.10.tar.gz ]; then
        cp -rf $1/lc_program/ovs-xs1.6.10.tar.gz      $lcforxen > /dev/null
    fi
    if [ -e $1/lc_program/ovs-xs1.8.0.tar.gz ]; then
        cp -rf $1/lc_program/ovs-xs1.8.0.tar.gz       $lcforxen > /dev/null
    fi
    if [ -e $1/lc_program/ovs-centos7.tar.gz ]; then
        cp -rf $1/lc_program/ovs-centos7.tar.gz     $lcfornsp > /dev/null
    fi
    if [ -e $1/lc_program/ovs-centos7.tar.gz ]; then
        cp -rf $1/lc_program/ovs-centos7.tar.gz     $lcforkvm > /dev/null
    fi
    cp -rf $1/lc_program/xen_pack.tar.gz              $lcforxen > /dev/null
    cp -rf $1/lc_program/pyagexec.tar.gz              $lcforxen > /dev/null
    cp -rf $1/lc_program/kvm_pack.tar.gz              $lcforkvm > /dev/null
    cp -rf $1/lc_program/pyagexec.tar.gz              $lcforkvm > /dev/null
    cp -rf $1/lc_program/dfi_agent_pack.tar.gz        $lcforxen > /dev/null
    cp -rf $1/lc_program/livegate_pack.tar.gz         $lcforxen > /dev/null
    cp -rf $1/lc_program/livegate_pack.tar.gz         $lcfornsp > /dev/null
    if [ -e $1/lc_program/dfi_agent_nsp_pack.tar.gz ]; then
        cp -rf $1/lc_program/dfi_agent_nsp_pack.tar.gz  $lcfornsp > /dev/null
        cp -rf $1/lc_program/dfi_agent_nsp_pack.tar.gz  $lcforkvm > /dev/null
    fi
    cp -rf $1/lc_program/obj/healthcheck              $lckernel > /dev/null
    cp -rf $1/lc_program/obj/lcrmd                    $lckernel > /dev/null
    cp -rf $1/lc_program/obj/vmdriver                 $lckernel > /dev/null
    cp -rf $1/lc_program/obj/lcpd                     $lckernel > /dev/null
    cp -rf $1/lc_program/obj/lcmond                   $lckernel > /dev/null
    cp -rf $1/lc_program/obj/lcsnfd                   $lckernel > /dev/null
    cp -rf $1/lc_program/obj/charge                   $lckernel > /dev/null
    cp -rf $1/lc_program/obj/cashier                  $lckernel > /dev/null
    cp -rf $1/lc_program/obj/id_agent                 $lckernel > /dev/null
    cp -rf $1/lc_program/obj/postman                  $lckernel > /dev/null
    cp -rf $1/lc_program/obj/talker                   $lckernel > /dev/null
    cp -rf $1/lc_program/obj/storekeeper              $lckernel > /dev/null
    cp -rf $1/lc_program/obj/cashier                  $lckernel > /dev/null
    cp -rf $1/lc_program/obj/backup                   $lckernel > /dev/null
    cp -rf $1/lc_program/obj/painter                  $lckernel > /dev/null
    cp -rf $1/lc_program/obj/sdncontroller            $lckernel > /dev/null
    cp -rf $1/lc_program/obj/analyzer                 $lckernel > /dev/null
    cp -rf $1/lc_program/obj/exchange                 $lckernel > /dev/null
    
    cp -rf $1/lc_program/script/lc_cobbler_install.sh 		$lcscript > /dev/null
    cp -rf $1/lc_program/script/pacemaker             		$lcscript > /dev/null
    cp -rf $1/lc_program/script/upgrade               		$lcscript > /dev/null
    cp -rf $1/lc_program/script/db.sh                 		$lcscript > /dev/null
    cp -rf $1/lc_program/script/change_mysql_password.py 	$lcscript > /dev/null
    cp -rf $1/lc_program/script/sys_init.sh           		$lckernel > /dev/null
    cp -rf $1/lc_program/script/bss_oss_domain_synctool.sh 	$lcscript > /dev/null
    cp -rf $1/lc_program/script/lc_customized_kvmos.sh 		$lcscript > /dev/null
    cp -rf $1/lc_program/script/lc_customized_block.sh 		$lcscript > /dev/null
    cp -rf $1/lc_program/script/bss_oss_ps_synctool.sh 		$lcscript > /dev/null
    cp -rf $1/lc_program/script/check_bss_product_specification.sh \
                                                    		$lcscript > /dev/null
    cp -rf $1/lc_program/script/vnckill.sh            		$lcscript > /dev/null
    cp -rf $1/lc_program/script/vnctunnel.sh          		$lcscript > /dev/null
    cp -rf $1/lc_program/script/vm_export.sh          		$lcscript > /dev/null
    cp -rf $1/lc_program/script/vm_revert.sh          		$lcscript > /dev/null
    cp -rf $1/lc_program/script/lc_xen_makeiso.sh     		$lcscript > /dev/null
    ( cd $1/lc_program/obj;
      tar czf $lcscript/vagent.tar.gz vagent/ --exclude=lb* --exclude=haproxy*;
      tar czf $lcscript/lb_vagent.tar.gz vagent/ )
    cp -rf $1/lc_program/script/lc_xen_iso.sh         $lcscript > /dev/null
    cp -rf $1/lc_program/script/lc_xen_gwiso.sh       $lcscript > /dev/null
    cp -rf $1/lc_program/script/nas_storage.sh        $lcscript > /dev/null
    cp -rf $1/lc_program/script/get_isp_conf.sh       $lcscript > /dev/null
    cp -rf $1/lc_program/script/lc_xen_vm_learning.sh $lcscript > /dev/null
    cp -rf $1/lc_program/script/lc_xen_vm_metadata.sh $lcscript > /dev/null
    cp -rf $1/lc_program/script/lc_process_check.sh   $lcscript > /dev/null
    cp -rf $1/lc_program/script/lc_vnc_check.sh       $lcscript > /dev/null
    cp -rf $1/lc_program/script/report_sendmail.sh    $lcscript > /dev/null
    cp -rf $1/lc_program/script/lc.sh                 $lcscript > /dev/null
    cp -rf $1/lc_program/script/lc/*                  $lcscript/lc > /dev/null
    cp -rf $1/lc_program/script/issu/*                $lcscript/issu > /dev/null
    cp -rf $1/lc_program/script/debug/*               $lcscript/debug > /dev/null
    cp -rf $1/lc_program/script/hwdev                 $lcscript/ > /dev/null
    cp -rf $1/lc_program/script/vmwaf                 $lcscript > /dev/null
    cp -rf $1/lc_program/script/vm_migrate.py         $lcscript > /dev/null
    cp -rf $1/lc_program/script/vmware_console.sh     $lcscript > /dev/null
    cp -rf $1/lc_program/script/vmware_vnctunnel.sh   $lcscript > /dev/null
    cp -rf $1/lc_program/script/vfw_webui_connect.sh  $lcscript > /dev/null
    cp -rf $1/lc_program/script/vfw_webui_close.sh    $lcscript > /dev/null
    cp -rf $1/lc_program/script/disk_create.sh        $lcscript > /dev/null
    cp -rf $1/lc_program/script/disk_extend.sh        $lcscript > /dev/null
    cp -rf $1/lc_program/script/disk_opt_intro        $lcscript > /dev/null
    cp -rf $1/lc_program/script/xen_templatectl.sh            $lcscript > /dev/null
    cp -rf $1/lc_program/script/bss_oss_domain_synctool.sh    $lcscript > /dev/null

    rm -f /bin/bss_oss_domain_synctool 2>/dev/null
    rm -f /bin/lc_customized_kvmos 2>/dev/null
    rm -f /bin/lc_customized_block 2>/dev/null
    rm -f /bin/bss_oss_ps_synctool 2>/dev/null
    rm -f /bin/check_bss_product_specification 2>/dev/null
    ln -s $lcscript/bss_oss_domain_synctool.sh /bin/bss_oss_domain_synctool >/dev/null
    ln -s $lcscript/lc_customized_kvmos.sh /bin/lc_customized_kvmos >/dev/null
    ln -s $lcscript/lc_customized_block.sh /bin/lc_customized_block >/dev/null
    ln -s $lcscript/bss_oss_ps_synctool.sh /bin/bss_oss_ps_synctool >/dev/null
    ln -s $lcscript/check_bss_product_specification.sh /bin/check_bss_product_specification >/dev/null
    
    cp -rf $1/lc_program/script/lc_customized_kvmos.sh 			$lcscript > /dev/null
    cp -rf $1/lc_program/script/lc_customized_block.sh  		$lcscript > /dev/null
    cp -rf $1/lc_program/script/kvm_templatectl.sh            	$lcscript > /dev/null
    cp -rf $1/lc_program/script/lc_xen_template_chk.sh        	$lcscript > /dev/null
    cp -rf $1/lc_program/script/lc_template_mangement.sh      	$lcscript > /dev/null
    cp -rf $1/lc_program/script/change_mysql_password.py      	$lcscript > /dev/null
    cp -rf $1/lc_program/script/ipmi_shutdown_host.sh         	$lcscript > /dev/null
    cp -rf $1/lc_program/script/ha/lc_backup_ontime.sh   		$lchascript > /dev/null
    cp -rf $1/lc_program/script/ha/ha_config_slave_controller.sh   $lchascript > /dev/null
    cp -rf $1/lc_program/script/ha/ha_recover_controller.sh   	$lchascript > /dev/null
    cp -rf $1/lc_program/script/ha/ha_snapshot_controller.sh   	$lchascript > /dev/null
    cp -rf $1/lc_program/script/ha/ha_config_repli_filter.sh   	$lchascript > /dev/null
    cp -rf $1/lc_program/script/ha/ha_config_mongodb.sh        	$lchascript > /dev/null
    cp -rf $1/lc_program/script/ha/ha_config_mongodb_repli.sh  	$lchascript > /dev/null
    cp -rf $1/lc_program/script/ha/lc_ha.sh                    	$lchascript > /dev/null
    cp -rf $1/lc_program/script/diskmgmt/*            			$lcdmscript > /dev/null
    cp -rf $1/lc_program/script/setif.sh              			$lcscript > /dev/null
    cp -rf $1/lc_program/script/get_ovs_info.sh       			$lcscript > /dev/null
    cp -rf $1/lc_program/script/lc_devctl.sh          $lcscript > /dev/null
    cp -rf $1/lc_program/script/lc_xenctl_ovs_update.sh $lcscript > /dev/null
    cp -rf $1/lc_program/script/lc_nspctl_ovs_update.sh $lcscript > /dev/null
    cp -rf $1/lc_program/script/lc_xenctl_install.sh  $lcscript > /dev/null
    cp -rf $1/lc_program/script/lc_nspctl_install.sh  $lcscript > /dev/null
    cp -rf $1/lc_program/script/lc_kvmctl_install.sh  $lcscript > /dev/null
    cp -rf $1/lc_program/script/xen_init.sh           $lcscript > /dev/null
    cp -rf $1/lc_program/script/xenbr_config.sh       $lcscript > /dev/null
    cp -rf $1/lc_program/script/xen_etc_xensource_scripts_vif  $lcscript > /dev/null
    cp -rf $1/lc_program/script/nsp_init.sh           $lcfornsp > /dev/null
    cp -rf $1/lc_program/script/nspbr_config.sh       $lcfornsp > /dev/null
    cp -rf $1/lc_program/script/nsp_network           $lcfornsp > /dev/null
    cp -rf $1/lc_program/script/sys_init.sh           $lckernel > /dev/null
    cp -rf $1/lc_program/script/trigger_insert_domain.sh           $lcscript > /dev/null
    cp -rf $1/lc_program/script/livecloud             $lckernel > /dev/null
    cp -rf $1/lc_program/db/sql_init_cmd              $lcconfig > /dev/null
    if [ -e /tmp/livecloud.conf.* ]; then
        mv /tmp/livecloud.conf.* $lcconfig/
    fi
    cp -rf $1/lc_program/script/conf/livecloud.conf   $lcconfig > /dev/null
    cp -rf $1/lc_program/script/conf/xen_pool.conf    $lcconfig > /dev/null
    cp -rf $1/lc_program/script/conf/xen_agent_log.conf    $lcconfig > /dev/null
    cp -rf $1/lc_program/script/conf/xen_agent_log_rotate  $lcconfig > /dev/null
    cp -rf $1/lc_program/script/conf/log.conf         /etc/rsyslog.d > /dev/null
    cp -rf $1/lc_program/script/conf/lc_log           /etc/logrotate.d > /dev/null
    cp -rf $1/lc_program/mntnct/mntnct                /usr/local/bin > /dev/null
    cp -rf $1/lc_program/mntnct/bash-completion/*     /usr/share/bash-completion/ > /dev/null
    mkdir -p $lckernel/mntnct >/dev/null
    cp -rf $1/lc_program/mntnct/{dialog,mtps.py}      $lckernel/mntnct/ >/dev/null
    cp -rf $1/lc_program/mntnct/{pymt,mt.py}          $lckernel/mntnct/ >/dev/null
    ln -sf $lckernel/mntnct/mtps.py /usr/local/bin/mtps >/dev/null
    ln -sf $lckernel/mntnct/mt.py /usr/local/bin/mt >/dev/null
    (cd $1/lc_program/gateway; ./lcc_install.sh 2>&1 >/dev/null)
    if [ ! -h /etc/bash_completion.d/mntnct ]; then
        ln -s /usr/share/bash-completion/mntnct /etc/bash_completion.d/mntnct
    fi
    chmod -R 755 $lcsys >/dev/null
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    return 0
}

install_keystone_db(){
    rm -f /tmp/bss.sql.tmp
    if [[ -f "/usr/bin/keystone-all" ]]; then
        cat << STRING >> /tmp/bss.sql.tmp
drop database if exists keystone;
create database keystone;
grant all on keystone.* to 'keystone'@'localhost' identified by 'livecloud';
STRING
        mysql -uroot -psecurity421 < /tmp/bss.sql.tmp
        rm -f /tmp/bss.sql.tmp
        echo -n "keystone database sync ... "
        keystone-manage db_sync >> $INSTALL_LOG 2>&1
        if [[ $? -eq 0 ]];then
            echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
        else
            echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
        fi
    fi
}


install_bss_db(){
    bss_sql='/var/www/lcweb_bss/lcweb_bss_sql_init'
    mysql -uroot -psecurity421 < $bss_sql
}

init_identifycode(){
    echo "generating 1000 initial identifycode..."
    curl --header "X-FROM: appserver" -s -X GET -k http://127.0.0.1/identifycode/generate >  /dev/null
}

__sys_install () {

    livecloud stop 2> /dev/null
    if [ -e $lcconfig/livecloud.conf ]; then
        mv $lcconfig/livecloud.conf /tmp/livecloud.conf.`date +20'%y%m%d%H%M%S'`
    fi
    rm -rf $lcsys > /dev/null
    __sys_check -m os
    __sys_check -m network
    path="`pwd`/lc_release"
    if [ -d $path ]; then
        if [ -d $path/lc_program ] && [ -d $path/lcweb ] && [ -d $path/state_sniffer ] && [ -d $path/lcwebapi ] \
        && [ -d $path/3parties ] ; then
            #install_packages $path

            install_webpages $path
            install_lcwebapi $path
            install_programs $path
            init_system $path
            install_bss_db
			install_keystone_db
            init_identifycode

        else
            echo "ERROR ($command): $path's modules are not integral"
            exit 1
        fi
    else
        echo "ERROR ($command): $path is not found"
        exit 1
    fi
    echo "Livecloud is completely installed!"
    echo -e 'Please config \033[0;32m/usr/local/livecloud/conf/livecloud.conf\033[0m first.'
    echo -e "The past files are saved in the directory $lcconfig"
    echo -e 'Please config ntp with \033[0;32m/usr/local/livecloud/script/upgrade/lc_host_ntp.sh\033[0m'
    echo "Then use 'livecloud start' to launch it if necessary."
    echo "Note: The mysql database is left untouched or not initialized."
    return 0
}

# config_stats_server $path 172.16.2.207
config_stats_server () {
    typeset lc_release_path controller_control_ip
    lc_release_path=$1
    controller_control_ip=$2

    echo -n "Configuring InfluxDB ... "
    rm -rf /etc/influxdb/influxdb.conf &&
    \cp -rf $lc_release_path/lc_program/script/conf/stats/influxdb.conf /etc/influxdb/ > /dev/null
    sed -i "s/__CONTROLLER_CONTROL_IP__/$controller_control_ip/g" /etc/influxdb/influxdb.conf
    systemctl enable influxdb & >> $INSTALL_LOG
    systemctl restart influxdb & >> $INSTALL_LOG
    if [[ $? -eq 0 ]]; then
        echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    else
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
    fi

    echo -n "Configuring telegraf ... "
    rm -rf /etc/telegraf/telegraf.conf &&
    \cp -rf $lc_release_path/lc_program/script/conf/stats/telegraf.conf /etc/telegraf/ > /dev/null
    sed -i "s/__CONTROLLER_CONTROL_IP__/$controller_control_ip/g" /etc/telegraf/telegraf.conf
    for ((it = 1; it <= 6; it += 1)); do
        err=`influx -host $controller_control_ip -port 20044 -execute 'CREATE DATABASE IF NOT EXISTS telegraf' 2>&1`
        if [[ $? -eq 0 && -z "$err" ]] || [[ $it -eq 6 ]]; then
            if [[ -n "$err" ]]; then
                echo "Failed to connect InfluxDB: $err"
                echo "Execute the following command to ensure \`telegraf' is created in influxdb:"
                echo "influx -host $controller_control_ip -port 20044 -execute 'CREATE DATABASE IF NOT EXISTS telegraf'"
            fi
            break
        else
            sleep 10
        fi
    done
    systemctl enable telegraf &>> $INSTALL_LOG
    systemctl restart telegraf &>> $INSTALL_LOG
    if [[ $? -eq 0 ]]; then
        echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    else
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
    fi

    echo -n "Configuring Elasticsearch ... "
    rm -rf /etc/elasticsearch/elasticsearch.yml > /dev/null  &&
    \cp -rf $lc_release_path/lc_program/script/conf/stats/elasticsearch.yml /etc/elasticsearch/ > /dev/null
    sed -i "s/__CONTROLLER_CONTROL_IP__/$controller_control_ip/g" /etc/elasticsearch/elasticsearch.yml
    systemctl enable elasticsearch &>> $INSTALL_LOG
    systemctl restart elasticsearch &>> $INSTALL_LOG
    if [[ $? -eq 0 ]]; then
        echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    else
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
    fi

    echo -n "Configuring analyzer conf ... "
    sed -i "/elasticsearch_server_list[ ]*=/c elasticsearch_server_list = $controller_control_ip" \
        /usr/local/livecloud/conf/livecloud.conf
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'

    echo -n "Configuring Kibana ... "
    rm -rf /opt/kibana/config/kibana.yml > /dev/null && 
    \cp -rf $lc_release_path/lc_program/script/conf/stats/kibana.yml /opt/kibana/config/ > /dev/null
    sed -i "s/__CONTROLLER_CONTROL_IP__/$controller_control_ip/g" /opt/kibana/config/kibana.yml
    sh $lc_release_path/lc_program/script/conf/stats/kibana_init.sh $controller_control_ip &>> $INSTALL_LOG
    systemctl enable kibana &>> $INSTALL_LOG
    systemctl restart kibana &>> $INSTALL_LOG
    if [[ $? -eq 0 ]]; then
        echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    else
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
    fi

    echo -n "Configuring Grafana ... "
    rm -rf /etc/grafana/grafana.ini > /dev/null && 
    \cp -rf $lc_release_path/lc_program/script/conf/stats/grafana.ini /etc/grafana/ > /dev/null
    mysql -e "GRANT ALL PRIVILEGES ON grafana.* TO 'grafana'@'localhost' IDENTIFIED BY 'grafana' WITH GRANT OPTION;" > /dev/null
    mysql -e "SOURCE $lc_release_path/lc_program/script/conf/stats/grafana.sql;" > /dev/null
    mysql -e "USE grafana; UPDATE data_source SET url = 'http://$controller_control_ip:20044'" > /dev/null
    systemctl enable grafana-server &>> $INSTALL_LOG
    systemctl restart grafana-server &>> $INSTALL_LOG
    if [[ $? -eq 0 ]]; then
        echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    else
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
    fi

    echo -n "Configuring mongo db ... "
    sed -i "/^bind_ip[ ]*=[ ]*.*/d" /etc/mongod.conf
    sed -i "/port[ ]\{0,\}=/c port = 20011\nbind_ip = 127.0.0.1,$controller_control_ip" /etc/mongod.conf
    sed -i "/pidfilepath[ ]*=/c pidfilepath=\/var\/run\/mongodb\/mongod.pid" /etc/mongod.conf
    sed -i "/logpath=/c logpath=\/var\/log\/mongo\/mongod.log" /etc/mongod.conf
    mkdir -p /var/log/mongo/
    chown mongodb:mongodb /var/log/mongo/
    systemctl enable mongod &>> $INSTALL_LOG
    systemctl restart mongod &>> $INSTALL_LOG
    if [[ $? -eq 0 ]]; then
        check=`grep logpath /etc/mongod.conf`
        if [ -z "$check" ]; then
            echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
        else
            echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
        fi
    else
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
    fi

    echo -n "Restoring mongo corpus table (ip_info_v2_2) ... "
    cd $lc_release_path/packages/corpus/ip_info/
    ./dboperation.sh restore &>> $INSTALL_LOG
    if [[ $? -eq 0 ]]; then
        echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    else
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
    fi
    cd -
}

config_mysql_config_file () {
    datadir_blackhole="/var/lib/mysql_2"
    tmpconf="/tmp/my.cnf"
    # Create a tmp config file and write configuration parameters of mysql to the file
    if [ -e $tmpconf ];then
        rm -f $tmpconf
    fi
    touch $tmpconf
    chmod 600 $tmpconf
    echo "[client]" >> $tmpconf
    echo -e "default-character-set=utf8" >> $tmpconf
    echo -e "user=$sqlusername" >> $tmpconf
    echo -e "password=$sqlpassword" >> $tmpconf

    echo "[mysql_upgrade]" >> $tmpconf
    echo -e "user=$sqlusername" >> $tmpconf
    echo -e "password=$sqlpassword" >> $tmpconf

    echo "[mysqld]" >> $tmpconf
    echo -e "datadir=/var/lib/mysql" >> $tmpconf
    echo -e "socket=/var/lib/mysql/mysql.sock" >> $tmpconf
    echo -e "user=mysql" >> $tmpconf
    echo -e "port=20130" >> $tmpconf
    echo -e "#enable query cache" >> $tmpconf
    echo -e "query_cache_type=1" >> $tmpconf
    echo -e "query_cache_size=64M" >> $tmpconf
    echo -e "innodb_buffer_pool_size=20M" >> $tmpconf
    echo -e "max_connections=512" >> $tmpconf
    echo -e "# Disabling symbolic-links is recommended to prevent assorted security risks" >> $tmpconf
    echo -e "symbolic-links=0" >> $tmpconf
    echo -e "server-id=1" >> $tmpconf
    echo -e "log-bin=mysql-bin" >> $tmpconf
    echo -e "log-bin-index=mysql-bin.index" >> $tmpconf
    echo -e "max_binlog_size=104857600" >> $tmpconf
    echo -e "log_warnings=1" >> $tmpconf
    echo -e "innodb_flush_log_at_trx_commit=1" >> $tmpconf
    echo -e "sync_binlog=1" >> $tmpconf
    echo -e "binlog_format=STATEMENT" >> $tmpconf
    echo -e "auto_increment_increment=1" >> $tmpconf
    echo -e "auto_increment_offset=1" >> $tmpconf
    echo -e "binlog-do-db=livecloud" >> $tmpconf
    echo -e "binlog-do-db=livecloud_bss" >> $tmpconf
    echo -e "binlog-do-db=livecloud_openstack" >> $tmpconf
    echo -e "binlog-ignore-db=mysql" >> $tmpconf
    echo -e "slow_query_log=ON" >> $tmpconf
    echo -e "slow_query_log_file=/var/lib/mysql/mysqld-slow.log" >> $tmpconf
    echo -e "long_query_time=1" >> $tmpconf
    echo -e "log-error=/var/log/mariadb/mariadb.log" >> $tmpconf
    echo -e "pid-file=/var/run/mariadb/mariadb.pid" >> $tmpconf
    echo -e "expire_logs_days=5" >> $tmpconf
    echo "#endof[mysqld]" >> $tmpconf

    systemctl stop mariadb 2>&1 > /dev/null
    killall mysqld 2> /dev/null
    sleep 8

    # To remove blackhole datadir...
    rm -rf $datadir_blackhole

    # Copy the configuration file to main controller
    rm -f /usr/my.cnf
    rm -f /etc/my.cnf
    cp $tmpconf /etc/
    chown :mysql /etc/my.cnf
	chmod g+r /etc/my.cnf
    
    systemctl start mariadb
    sleep 2
    CHECK=`ps -A | grep mysqld`
    if [ -z "$CHECK" ]; then
        echo "$LINENO Error: Failed to start mysqld."
        exit 1
    fi
    return 0
}

config_cgroups_limit_src () {
    echo -n "Config cgroups for limiting resource used by agent"
    cat<<cgroup_lcsnfd_agent > /etc/cgconfig.conf
group lcsnfd-agent{
	cpu {
		cpu.cfs_quota_us = 20000;
    }
    memory {
        memory.limit_in_bytes = 128m;
		memory.memsw.limit_in_bytes = 256m;
    }
}
cgroup_lcsnfd_agent

    cat<<cgroup_lcsnfd_agent > /etc/cgrules.conf
*:lcsnfd       cpu,memory         lcsnfd-agent/
cgroup_lcsnfd_agent

    systemctl enable cgconfig &>> $INSTALL_LOG
    systemctl enable cgred &>> $INSTALL_LOG
    systemctl restart cgconfig &>> $INSTALL_LOG
    systemctl restart cgred &>> $INSTALL_LOG
    if [[ $? -eq 0 ]]; then
        echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    else
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
    fi
}

init_system () {
    lc_release_path=$1
    typeset conf check
    echo -n "Configuring email system ... "
    check=`grep "smtp.exmail.qq.com" /etc/mail.rc`
    if [ -z "$check" ]; then
        echo "set smtp=smtp.exmail.qq.com" >> /etc/mail.rc
        echo "set from=stats@yunshan.net.cn" >> /etc/mail.rc
        echo "set smtp-auth-user=stats@yunshan.net.cn smtp-auth-password=yunshan3302 smtp-auth=login" >> /etc/mail.rc
    fi
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'

    echo -n "Configuring schedule ... "
    sed -i "/lc_process_check.sh/d" /etc/crontab
    sed -i "/lc_vnc_check.sh/d" /etc/crontab
    echo "0 2 * * * root /usr/local/livecloud/script/lc_vnc_check.sh >/dev/null 2>&1" >>/etc/crontab
    sed -i "/lc_backup_ontime.sh/d" /etc/crontab
    echo "0 3 * * * root /usr/local/livecloud/script/ha/lc_backup_ontime.sh $lcbackupdir $sqlusername $sqlpassword" >> /etc/crontab
    sed -i "/lc_db_backup_ontime.sh/d" /etc/crontab
    echo "0 2 * * * root /usr/local/livecloud/script/lc_db_backup_ontime.sh" >> /etc/crontab
    sed -i "/identifycode/d" /etc/crontab
    echo "0 1 * * * root curl -X GET -k http://127.0.0.1/identifycode/generate > /dev/null 2>&1" >> /etc/crontab
    sed -i "/nas_storage.sh/d" /etc/crontab
    echo "*/10 * * * * root /usr/local/livecloud/script/nas_storage.sh /var/tmp/resource.json > /dev/null 2>&1" >> /etc/crontab
    service crond restart >/dev/null 2>&1
    if [[ "$?" -eq 0 ]]; then
        echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    else
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
    fi

    echo -n "Configuring iptables ... "
    systemctl enable firewalld &>> $INSTALL_LOG
    systemctl restart firewalld &>> $INSTALL_LOG
    firewall-cmd --permanent --zone=public --add-port=25000-33000/tcp &>> $INSTALL_LOG
	firewall-cmd --permanent --zone=public --add-port=22/tcp &>> $INSTALL_LOG
	firewall-cmd --permanent --zone=public --add-port=80/tcp &>> $INSTALL_LOG
	firewall-cmd --permanent --zone=public --add-port=443/tcp &>> $INSTALL_LOG
	firewall-cmd --permanent --zone=public --add-port=4369/tcp &>> $INSTALL_LOG
	firewall-cmd --permanent --zone=public --add-port=53/tcp &>> $INSTALL_LOG
	firewall-cmd --permanent --zone=public --add-port=623/tcp &>> $INSTALL_LOG
	firewall-cmd --permanent --zone=public --add-port=123/tcp &>> $INSTALL_LOG
	firewall-cmd --permanent --zone=public --add-port=161/udp &>> $INSTALL_LOG
	firewall-cmd --permanent --zone=public --add-port=5666/tcp &>> $INSTALL_LOG
	firewall-cmd --permanent --zone=public --add-port=20000-20149/tcp &>> $INSTALL_LOG
	firewall-cmd --permanent --zone=public --add-port=20000-20149/udp &>> $INSTALL_LOG
	
	firewall-cmd --permanent --zone=public --add-port=22901-23299/tcp &>> $INSTALL_LOG
	firewall-cmd --permanent --zone=public --add-port=10900-12899/tcp &>> $INSTALL_LOG
	firewall-cmd --permanent --zone=public --add-port=10900-12899/tcp &>> $INSTALL_LOG
	firewall-cmd --permanent --zone=public --add-port=20900-22899/tcp &>> $INSTALL_LOG
	firewall-cmd --permanent --zone=public --add-port=25000-33000/tcp &>> $INSTALL_LOG
	firewall-cmd --permanent --zone=public --add-port=43003/tcp &>> $INSTALL_LOG
	firewall-cmd --reload &>> $INSTALL_LOG
	
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/98-sysctl.conf
    if [[ "$?" -eq 0 ]]; then
        echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    else
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
    fi

    echo -n "Configuring NTP ... "
    ifcfg_file="/etc/sysconfig/network-scripts/ifcfg-$controller_control_interface"
    address=`grep IPADDR $ifcfg_file | cut -d= -f2`
    netmask=`grep NETMASK $ifcfg_file | cut -d= -f2`
    nw_addr=`echo "$address.$netmask" |
             awk -F'.' '{ print and($1,$5)"."and($2,$6)"."and($3,$7)"."and($4,$8) }'`
    cat << string >/etc/ntp.conf
driftfile /var/lib/ntp/drift

restrict default ignore
restrict -6 default ignore
restrict 127.0.0.1
restrict -6 ::1

restrict ntp.sjtu.edu.cn nomodify notrap noquery
server   ntp.sjtu.edu.cn
restrict 1.cn.pool.ntp.org nomodify notrap noquery
server   1.cn.pool.ntp.org
restrict 2.cn.pool.ntp.org nomodify notrap noquery
server   2.cn.pool.ntp.org
restrict 3.cn.pool.ntp.org nomodify notrap noquery
server   3.cn.pool.ntp.org
restrict 0.cn.pool.ntp.org nomodify notrap noquery
server   0.cn.pool.ntp.org
restrict cn.pool.ntp.org nomodify notrap noquery
server   cn.pool.ntp.org

restrict $nw_addr mask $netmask nomodify notrap
server   127.127.1.0    # local clock
fudge    127.127.1.0 stratum 10
string
    systemctl enable ntpd &>> $INSTALL_LOG
	systemctl restart ntpd &>> $INSTALL_LOG
    if [[ "$?" -eq 0 ]]; then
        echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    else
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
    fi

    echo -n "Configuring mysql ... "
    ls /var/run | grep mariadb 2>&1 > /dev/null
    if [ $? -ne 0 ]; then
        mkdir -p /var/run/mariadb
        chown mariadb:mariadb /var/run/mariadb
    fi
    systemctl enable mariadb &>> $INSTALL_LOG
    systemctl restart mariadb &>> $INSTALL_LOG
    mysql -e \
        "GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' IDENTIFIED BY 'security421' WITH GRANT OPTION;" > /dev/null
    echo "To generate the configuration file of mysql." >> $INSTALL_LOG
    config_mysql_config_file

    check=`ls ~ | grep "livecloud5_1.sql"`
    if [ -n "$check" ]; then
        mysql_upgrade > /dev/null 2>&1
        systemctl restart mariadb
    fi

    #mysql -u$sqlusername -p$sqlpassword < $lcconfig/sql_init_cmd > /dev/null
    mysql -e \
        "GRANT ALL PRIVILEGES ON *.* TO 'admin'@'localhost' IDENTIFIED BY 'security421' WITH GRANT OPTION;" > /dev/null
    mysql -e \
        "GRANT SELECT ON livecloud.* TO 'guest'@'localhost' IDENTIFIED BY 'guest';" > /dev/null
    mysql -e \
        "FLUSH PRIVILEGES;" > /dev/null
    if [[ $? -eq 0 ]]; then
        echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    else
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
    fi

    config_stats_server $lc_release_path $controller_control_ip
    config_cgroups_limit_src

    echo -n "Configuring LLDP"
    systemctl enable lldpad &>> $INSTALL_LOG
    systemctl restart lldpad &>> $INSTALL_LOG
    for i in `ls /sys/class/net/ | grep -v lo` ;
    	do echo "enabling lldp for interface: $i" >> $INSTALL_LOG
    	lldptool set-lldp -i $i adminStatus=tx &>> $INSTALL_LOG
    	lldptool -T -i $i -V sysName enableTx=yes &>> $INSTALL_LOG
    	lldptool -T -i $i -V portDesc enableTx=yes &>> $INSTALL_LOG
    	lldptool -T -i $i -V sysDesc enableTx=yes &>> $INSTALL_LOG
    	lldptool -T -i $i -V sysCap enableTx=yes &>> $INSTALL_LOG
    	lldptool -T -i $i -V mngAddr enableTx=yes &>> $INSTALL_LOG
    	lldptool -T -i $i -V portID subtype=PORT_ID_INTERFACE_NAME &>> $INSTALL_LOG
	done
	echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    
    echo -n "Configuring rabbitmq-server ... "
    rabbitmqctl stop_app 2&> /dev/null
    rabbitmqctl reset 2&> /dev/null
    systemctl stop rabbitmq-server 2&> /dev/null
    epmd -names 2> /dev/null | grep -Eo "^name \w+ at " | awk '{print $2}' | while read node_name; do
        epmd -stop $node_name
    done
    pkill -9 beam.smp
    pkill -9 beam
    pkill -9 epmd
    sed -i "/^127.0.0.1 `hostname -s`$/d" /etc/hosts
    sed -i "/^::1 `hostname -s`$/d" /etc/hosts
    echo -e "127.0.0.1 `hostname -s`\n::1 `hostname -s`" >> /etc/hosts
    echo "[
  {mnesia, [{dump_log_write_threshold, 1000}]},
  {kernel, [{inet_dist_listen_min, 20020},{inet_dist_listen_max, 20030}]}
]." > /etc/rabbitmq/rabbitmq.config
    echo -e "ERL_EPMD_PORT=20010\nNODENAME=livecloud@`hostname -s`\nNODE_IP_ADDRESS=127.0.0.1\nNODE_PORT=20001" > \
        /etc/rabbitmq/rabbitmq-env.conf
    systemctl enable rabbitmq-server &>> $INSTALL_LOG
    systemctl restart rabbitmq-server &>> $INSTALL_LOG
    if [[ $? -eq 0 ]]; then
        echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    else
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
    fi

    echo -n "Configuring syslog ... "
    sed -i 's/^\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat/#\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat/' /etc/rsyslog.conf
    sed -i '/yunshanformat/d' /etc/rsyslog.conf
    sed -i '/ActionFileDefaultTemplate/i \$template yunshanformat, \"%\$NOW%|%TIMESTAMP:8:15%|%hostname%|%syslogtag%|%msg%\\n\"' /etc/rsyslog.conf
    sed -i '/ActionFileDefaultTemplate/i \$ActionFileDefaultTemplate yunshanformat' /etc/rsyslog.conf
    systemctl enable rsyslog &>> $INSTALL_LOG
    systemctl restart rsyslog &>> $INSTALL_LOG
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'

    echo -n "Configuring coredump ... "
    mkdir -p /corefile > /dev/null
    chmod -R 777 /corefile > /dev/null
    echo "/corefile/core-%e-%p-%t" > /proc/sys/kernel/core_pattern
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'

    echo -n "Configuring tcp parameter ... "
    CFGFILE=/etc/sysctl.d/98-sysctl.conf
    #Sometime lcmonitor will be stalled to call recv
    #because tcp fd couldn't close socket once the peer disappeared
    echo "net.ipv4.tcp_keepalive_time=120" >> $CFGFILE
    echo "net.ipv4.tcp_keepalive_probes=30" >> $CFGFILE
    echo "net.ipv4.tcp_keepalive_intvl=60" >> $CFGFILE
    sysctl -p &>> $INSTALL_LOG
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'

    echo -n "Configuring postman template ... "
    sed -i "s|email\.site_url *=.*|email\.site_url = https://${domain_name}/|g" \
        /usr/local/livecloud/conf/livecloud.conf
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    echo -n "Configuring local controller ip address ... "
    sed -i "/local_ctrl_ip[ ]*=/ c local_ctrl_ip = $controller_control_ip" \
        /usr/local/livecloud/conf/livecloud.conf
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'

    echo -n "Configuring alias ... "
    conf="/etc/bashrc"
    check=`grep -o "^alias mysqlc" $conf`
    if [ -z "$check" ]; then
        echo >> $conf
        echo "alias mysqlc='mysql -uguest -pguest -D livecloud'" >> $conf
    fi
    check=`grep -o "^alias seelcrmd" $conf`
    if [ -z "$check" ]; then
        echo "alias seelcrmd='tail -n 30 -f $lclog/lcrmd.log'" >> $conf
    fi
    check=`grep -o "^alias seevmdriver" $conf`
    if [ -z "$check" ]; then
        echo "alias seevmdriver='tail -n 30 -f $lclog/vm.log'" >> $conf
    fi
    check=`grep -o "^alias seelcpd" $conf`
    if [ -z "$check" ]; then
        echo "alias seelcpd='tail -n 30 -f $lclog/lcpd.log'" >> $conf
    fi
    check=`grep -o "^alias seelcmond" $conf`
    if [ -z "$check" ]; then
        echo "alias seelcmond='tail -n 30 -f $lclog/lcmond.log'" >> $conf
    fi
    check=`grep -o "^alias seelcsnfd" $conf`
    if [ -z "$check" ]; then
        echo "alias seelcsnfd='tail -n 30 -f $lclog/lcsnfd.log'" >> $conf
    fi
    check=`grep -o "^alias seepostman" $conf`
    if [ -z "$check" ]; then
        echo "alias seepostman='tail -n 30 -f $lclog/postman.log'" >> $conf
    fi
    check=`grep -o "^alias seetalker" $conf`
    if [ -z "$check" ]; then
        echo "alias seetalker='tail -n 30 -f $lclog/talker.log'" >> $conf
    fi
    check=`grep -o "^alias seestrkpr" $conf`
    if [ -z "$check" ]; then
        echo "alias seestrkpr='tail -n 30 -f $lclog/storekeeper.log'" >> $conf
    fi
    check=`grep -o "^alias seecashier" $conf`
    if [ -z "$check" ]; then
        echo "alias seecashier='tail -n 30 -f $lclog/cashier.log'" >> $conf
    fi
    check=`grep -o "^alias seebackup" $conf`
    if [ -z "$check" ]; then
        echo "alias seebackup='tail -n 30 -f $lclog/backup.log'" >> $conf
    fi
    check=`grep -o "^alias seepainter" $conf`
    if [ -z "$check" ]; then
        echo "alias seepainter='tail -n 30 -f $lclog/painter.log'" >> $conf
    fi
    check=`grep -o "^alias seesdncontroller" $conf`
    if [ -z "$check" ]; then
        echo "alias seesdncontroller='tail -n 30 -f $lclog/sdncontroller.log'" >> $conf
    fi
    check=`grep -o "^alias seeanalyzer" $conf`
    if [ -z "$check" ]; then
        echo "alias seeanalyzer='tail -n 30 -f $lclog/analyzer.log'" >> $conf
    fi
    check=`grep -o "^alias seeexchange" $conf`
    if [ -z "$check" ]; then
        echo "alias seeexchange='tail -n 30 -f $lclog/exchange.log'" >> $conf
    fi
    check=`grep -o "^alias seelcweb" $conf`
    if [ -z "$check" ]; then
        echo "alias seelcweb='tail -n 30 -f $lclog/lcweb.log'" >> $conf
    fi
    . $conf
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'

    echo -n "Configuring program stack size, core file, fd limit ..."
    sed -i "/ulimit -s/d" $conf
    echo "ulimit -s 20480" >> $conf
    sed -i "/ulimit -c/d" $conf
    echo "ulimit -c unlimited" >> $conf
    sed -i "/ulimit -n/d" $conf
    echo "ulimit -n 65536" >> $conf
    . $conf
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'

    echo -n "Configuring bash history ..."
    sed -i "/^shopt -s histappend/d" $conf
    sed -i "/^HISTFILESIZE=/d" $conf
    sed -i "/^HISTSIZE=/d" $conf
    sed -i "/^export HISTTIMEFORMAT=/d" $conf
    echo "shopt -s histappend" >> $conf
    echo "HISTFILESIZE=8192" >> $conf
    echo "HISTSIZE=4096" >> $conf
    echo "export HISTTIMEFORMAT=\"%F %T: \"" >> $conf
    . $conf
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'

    echo -n "Configuring sshpass ... "
    rm -rf ~/.ssh/known_hosts > /dev/null
    conf="/etc/ssh/ssh_config"
    check=`grep -o "^#   StrictHostKeyChecking ask" $conf`
    if [ -z "$check" ]; then
        check=`grep -o "^    StrictHostKeyChecking no" $conf`
        if [ "$check" = "" ]; then
            echo "    StrictHostKeyChecking no" >> $conf
        fi
    else
        sed -i 's/^#   StrictHostKeyChecking ask/    StrictHostKeyChecking no/' $conf
    fi
    systemctl restart sshd &>> $INSTALL_LOG
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'

    echo -n "Installing livecloud ... "
    conf="/etc/rc.d/rc.local"
    sed -i "/sys_init.sh/d" $conf
    check=`grep -o "^$lckernel/sys_init.sh" $conf`
    if [ -z "$check" ]; then
        echo >> $conf
        echo "$lckernel/sys_init.sh" >> $conf
    fi
    if [ -f "/bin/livecloud" ]; then
        touch /bin/livecloud
    else
        ln -s $lckernel/livecloud /bin/livecloud
    fi
    # do not delete, so as to support downward compatibility
    if [ -L "/bin/lc-xenctl" ]; then
        rm -f /bin/lc-xenctl
    fi
    ln -s $lcscript/lc_devctl.sh /bin/lc-xenctl
    if [ -f "/bin/lc-devctl" ]; then
        touch /bin/lc-devctl
    else
        ln -s $lcscript/lc_devctl.sh /bin/lc-devctl
    fi
    if [ -f "/bin/lc-cobbler-install" ]; then
        touch /bin/lc-cobbler-install
    else
        ln -s $lcscript/lc_cobbler_install.sh /bin/lc-cobbler-install
    fi
    echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'

    echo "set public address of lcweb ..."
    SYSCONF="/usr/local/livecloud/conf/livecloud.conf"
    CONFIG="/var/www/lcweb/lcc/config.ini"
    SSL_BSS="/etc/nginx/conf.d/ssl-bss.conf"
    SSL_OSS="/etc/nginx/conf.d/ssl-oss.conf"

    sed -i "/^url =/s/url =.*/url = $public_ip_address_oss/" $CONFIG
    sed -i "/^bss.url =/s/bss.url =.*/bss.url = $public_ip_address_bss/" $CONFIG
    sed -i "/^bss.public_url =/s/bss.public_url =.*/bss.public_url = $public_ip_address_bss/" $CONFIG
    
    sed -i "s/error_page 404/rewrite \^\(\.\*\)\$  \
https:\/\/$public_ip_address_bss\$1 permanent;\n    error_page 404/" $SSL_BSS > /dev/null
    
    sed -i "s/error_page 404/rewrite \^\(\.\*\)\$  \
https:\/\/$public_ip_address_oss\$1 permanent;\n    error_page 404/" $SSL_OSS > /dev/null

    sed -i "s/local_public_ip = .*/local_public_ip = $public_ip_address_oss/" $SYSCONF > /dev/null
    sed -i "s|HOSTIP|$public_ip_address_bss|" $SSL_BSS
    sed -i "s|HOSTIP|$public_ip_address_oss|" $SSL_OSS
    systemctl restart nginx &>> $INSTALL_LOG
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
    setenable cashier
    setenable resourcejob
    setenable charge
    setdisable sdncontroller
    setdisable idagent
    setdisable vmwareadapter
    setdisable keystone
    setdisable azure
    
    return 0
}

setenable() 
{
    process=$1
    sed -i "s/$process = .*/$process = enable/" \
    /usr/local/livecloud/conf/livecloud.conf
}

setdisable() 
{
    process=$1
    sed -i "s/$process = .*/$process = disable/" \
    /usr/local/livecloud/conf/livecloud.conf
}

__sys_install