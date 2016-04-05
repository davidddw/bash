#!/bin/sh

FAILED='\033[60G[\033[0;31mFAILED\033[0m]'
OK='\033[60G[\x20 \033[0;32mOK\033[0m \x20]'
SSH="ssh -4 -a \
    -o ConnectTimeout=1 \
    -o VerifyHostKeyDNS=no \
    -o GSSAPIAuthentication=no \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR"

LIVECLOUD="/usr/local/livecloud"
LIVECLOUDWEB="/var/www"
LIVECLOUDLOG="/var/log"
LIVECLOUDCONF="$LIVECLOUD/conf/livecloud.conf"

DAEMON="[daemon]"

BINDIR="$LIVECLOUD/bin"
LIBDIR="$LIVECLOUD/lib"
WEBDIR="$LIVECLOUDWEB/lcweb"
BSSDIR="$LIVECLOUDWEB/lcweb_bss"
SCRIPTDIR="$LIVECLOUD/script"
source $SCRIPTDIR/db.sh
SQLEXEC="mysql -D livecloud -sNe"

PXE_DEVICE_TABLE="pxe_device_v$DBVER"
SYS_CONFIG_TABLE="sys_configuration_v$DBVER"
STACK_SIZE=20480

RESOURCE_JOB_SCRIPT="$BINDIR/resource-job-adapter.sh"
VMWARE_ADAPTER_SCRIPT="$BINDIR/vmware-adapter.sh"

MT="/usr/local/bin/mt"

TIMEVAL=0.3

# Text color variables
txtund=$(tput sgr 0 1)          # Underline
txtbld=$(tput bold)             # Bold
bld_black=${txtbld}$(tput setaf 0)
bld_red=${txtbld}$(tput setaf 1)
bld_green=${txtbld}$(tput setaf 2)
bld_yellow=${txtbld}$(tput setaf 3)
bld_blue=${txtbld}$(tput setaf 4)
bld_magenta=${txtbld}$(tput setaf 5)
bld_cyan=${txtbld}$(tput setaf 6)
bld_white=${txtbld}$(tput setaf 7)
wrap_info=${bld_blue}
wrap_pass=${bld_green}
wrap_warn=${bld_yellow}
wrap_err=${bld_red}
wrap_over=$(tput sgr0)
ERROR="${wrap_err}ERROR${wrap_over} [`date`]"
WARN="${wrap_warn}WARNING${wrap_over} [`date`]"
DONE="${wrap_pass}DONE${wrap_over} [`date`]"
STATUS_OK="[${wrap_pass}OK${wrap_over}]"
STATUS_ERR="[${wrap_err}ERROR${wrap_over}]"
STATUS_WARN="[${wrap_warn}WARNING${wrap_over}]"
STATUS_ENABLE="[${wrap_pass}ENABLE${wrap_over}]"
STATUS_DISABLE="[${wrap_err}DISABLE${wrap_over}]"
STATUS_RUNNING="[${wrap_pass}RUNNING${wrap_over}]"
STATUS_DOWN="[${wrap_err}DOWN${wrap_over}]"
MANUAL_CHECK="[${wrap_warn}CHECK${wrap_over}]"

DAEMONS=(lcrmd vmdriver lcpd lcmond lcsnfd postman talker storekeeper cashier
         backup painter analyzer resourcejob charge lcwebapi nodelistener
         idagent keystone sdncontroller exchange yynwadapter vmwareadapter
         cobbler)
flag=0
status_true='enable'
status_false='disable'
for daemon in ${DAEMONS[@]} httpd nginx; do
    typeset $daemon
    eval $daemon=$status_false
done
STR_DAEMONS=''
for daemon in ${DAEMONS[@]} environment; do
    STR_DAEMONS=$STR_DAEMONS$daemon' '
done

config_parse()
{
    __daemon=$1
    if [[ ! -f $LIVECLOUDCONF ]]; then
        echo "$ERROR: can not find livecloud.conf"
        exit 1
    fi

    while read line; do
        echo "$line" | grep -E '^[ ]*#' >/dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            continue
        fi

        if [[ -z "$line" ]]; then
            continue
        fi

        echo "$line" | grep -E '\[.*\]' >/dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            line=`echo "$line" | xargs echo`
            if [[ "$line" == "$DAEMON" ]]; then
                flag=1
            else
                flag=0
            fi
            continue
        fi

        if [[ $flag -eq 0 ]]; then
            continue
        fi

        check="`echo $line | awk -F '=' '{print $1}' | xargs echo`"
        if [[ -z "$__daemon" || "$__daemon" == "$check" ]]; then
            eval $check=`echo $line | awk -F '=' '{print $2}' | xargs echo`
        fi
    done < $LIVECLOUDCONF
}

set_db_system_state()
{
    # 3 to 7 are IDs in table sys_configuration
    for i in `seq 3 7`; do
        $DBEXEC "DELETE FROM $SYS_CONFIG_TABLE WHERE id=$i" >/dev/null 2>&1
    done
}

get_pid_by_port()
{
    proto=$1
    port=$2
    del=$3
    lsof -ti $proto:$port | awk -v DEL="$del" '{
        if (NR==1) printf "%s", $1
        else       printf "%s%s", DEL, $1
    }'
}

get_process_by_port()
{
    proto=$1
    port=$2
    pid_list=`get_pid_by_port $proto $port ,`
    ps -p $pid_list o pid=,comm= 2>$- | awk '{
        if (NR==1) printf "%s/%s", $1, $2
        else       printf ",%s/%s", $1, $2
    }'
}

get_process_by_listen_port()
{
    port=$1
    comms=(`netstat -anp | awk '{print $4,$7}' | grep ":$port " |
        awk '{print $2}' | awk -F'/' '{print $1}' | grep -Ex "[0-9]+" | sort | uniq`)
    echo "${comms[@]}"
}

get_pid_by_port_and_comm()
{
    proto=$1
    port=$2
    comm=$3
    del=$4
    lsof -ti $proto:$port -a -c $comm | awk -v DEL="$del" '{
        if (NR==1) printf "%s", $1
        else       printf "%s%s", DEL, $1
    }'
}

get_process_by_port_and_comm()
{
    proto=$1
    port=$2
    comm=$3
    pid_list=`get_pid_by_port_and_comm $proto $port $comm ,`
    ps -p $pid_list o pid=,comm= 2>$- | awk '{
        print $1"/"$2
    }'
}

command_ps()
{
    ps -eo pid,start,command | grep "$1" | grep -v grep | head -n 1
}

daemon_is_enabled()
{
    [[ "$1" == "$status_true" ]]
}

daemon_is_disabled()
{
    [[ "$1" != "$status_true" ]]
}

overview_daemon_status()
{
    daemon="$1"
    status="$2"
    if daemon_is_disabled $status; then
        info="$STATUS_DISABLE"
        return 0
    fi
    info="$STATUS_ENABLE"
    CHECK=`command_ps "$daemon"`
    if [[ -z "$CHECK" ]]; then
        echo -e "$info$STATUS_DOWN $daemon" >&2
    else
        echo -e "$info$STATUS_RUNNING $CHECK"
    fi
}

check_daemon_status()
{
    daemon="$1"
    status="$2"
    shift 2
    ports="$@"
    daemon_name=${daemon##*/}
    if daemon_is_disabled $status; then
        info="$STATUS_DISABLE"
    else
        info="$STATUS_ENABLE"
    fi
    CHECK=`command_ps "$daemon"`
    if [[ -z "$CHECK" ]]; then
        echo -e "$info$STATUS_DOWN $daemon" >&2
        for port in $ports; do
            process=`get_process_by_port tcp $port`
            if [[ -n "$process" ]]; then
                echo -e "$STATUS_ERR $daemon: tcp port $port taken by $process" >&2
            fi
        done
        return 1
    else
        for port in $ports; do
            process=`get_process_by_port_and_comm tcp $port $daemon_name`
            if [[ -z "$process" ]]; then
                process=`get_process_by_port tcp $port`
            fi
            if [[ -z "$process" ]]; then
                echo -e "$STATUS_ERR $daemon: tcp port $port not used by $daemon_name" >&2
                return 1
            elif [[ "`echo $process | cut -d'/' -f2`" != "$daemon_name" ]]; then
                echo -e "$STATUS_ERR $daemon: tcp port $port taken by $process" >&2
                return 1
            fi
        done
    fi
    echo -e "$info$STATUS_RUNNING $CHECK"
}

check_lcrmd_status()
{
    daemon="$BINDIR/lcrmd"
    if [[ "$1" = "overview" ]]; then
        overview_daemon_status "$daemon" $lcrmd
    elif [[ "$1" = "details" ]]; then
        check_daemon_status "$daemon" $lcrmd
    fi
}

check_vmdriver_status()
{
    daemon="$BINDIR/vmdriver"
    if [[ "$1" = "overview" ]]; then
        overview_daemon_status "$daemon" $vmdriver
        return 0
    elif [[ "$1" = "details" ]]; then
        check_daemon_status "$daemon" $vmdriver 20004
    fi
}

check_lcpd_status()
{
    daemon="$BINDIR/lcpd"
    if [[ "$1" = "overview" ]]; then
        overview_daemon_status "$daemon" $lcpd
    elif [[ "$1" = "details" ]]; then
        check_daemon_status "$daemon" $lcpd 20005
    fi
}

check_lcmond_status()
{
    daemon="$BINDIR/lcmond"
    if [[ "$1" = "overview" ]]; then
        overview_daemon_status "$daemon" $lcmond
    elif [[ "$1" = "details" ]]; then
        check_daemon_status "$daemon" $lcmond
    fi
}

check_lcsnfd_status()
{
    daemon="$BINDIR/lcsnfd"
    if [[ "$1" = "overview" ]]; then
        overview_daemon_status "$daemon" $lcsnfd
        return 0
    elif [[ "$1" = "details" ]]; then
        check_daemon_status "$daemon" $lcsnfd 20006 20007
    fi
}

check_postman_status()
{
    daemon="$BINDIR/postman/postman.py"
    if [[ "$1" = "overview" ]]; then
        overview_daemon_status "$daemon" $postman
    elif [[ "$1" = "details" ]]; then
        check_daemon_status "$daemon" $postman
    fi
}

check_talker_status()
{
    daemon="$BINDIR/talker/talker.py"
    if [[ "$1" = "overview" ]]; then
        overview_daemon_status "$daemon" $talker
    elif [[ "$1" = "details" ]]; then
        check_daemon_status "$daemon" $talker 20013
    fi
}

check_storekeeper_status()
{
    daemon="$BINDIR/storekeeper/storekeeper.py"
    if [[ "$1" = "overview" ]]; then
        overview_daemon_status "$daemon" $storekeeper
    elif [[ "$1" = "details" ]]; then
        check_daemon_status "$daemon" $storekeeper
    fi
}

check_cashier_status()
{
    daemon="$BINDIR/cashier/cashier.py"
    if [[ "$1" = "overview" ]]; then
        overview_daemon_status "$daemon" $cashier
    elif [[ "$1" = "details" ]]; then
        check_daemon_status "$daemon" $cashier
    fi
}

check_backup_status()
{
    daemon="$BINDIR/backup/backup.py"
    if [[ "$1" = "overview" ]]; then
        overview_daemon_status "$daemon" $backup
    elif [[ "$1" = "details" ]]; then
        check_daemon_status "$daemon" $backup
    fi
}

check_painter_status()
{
    daemon="$BINDIR/painter/painter.py"
    if [[ "$1" = "overview" ]]; then
        overview_daemon_status "$daemon" $painter
    elif [[ "$1" = "details" ]]; then
        check_daemon_status "$daemon" $painter
    fi
}

check_analyzer_status()
{
    daemon="$BINDIR/analyzer/analyzer.py"
    if [[ "$1" = "overview" ]]; then
        overview_daemon_status "$daemon" $analyzer
    elif [[ "$1" = "details" ]]; then
        check_daemon_status "$daemon" $analyzer
    fi
}

check_resourcejob_status()
{
    daemon="$LIBDIR/resource-job"
    if [[ "$1" = "overview" ]]; then
        overview_daemon_status "$daemon" $resourcejob
    elif [[ "$1" = "details" ]]; then
        check_daemon_status "$daemon" $resourcejob
    fi
}

check_charge_status()
{
    daemon="node charge.js"
    if [[ "$1" = "overview" ]]; then
        overview_daemon_status "$daemon" $charge
    elif [[ "$1" = "details" ]]; then
        check_daemon_status "$daemon" $charge
    fi
}

check_lcwebapi_status()
{
    daemon="node app.js"
    if [[ "$1" = "overview" ]]; then
        overview_daemon_status "$daemon" $lcwebapi
    elif [[ "$1" = "details" ]]; then
        check_daemon_status "$daemon" $lcwebapi
    fi
}

check_nodelistener_status()
{
    daemon="node msgCenterlistener.js"
    if [[ "$1" = "overview" ]]; then
        overview_daemon_status "$daemon" $nodelistener
    elif [[ "$1" = "details" ]]; then
        check_daemon_status "$daemon" $nodelistener
    fi
}

check_lcweb_status()
{
    if [[ "$1" = "overview" ]]; then
        modules=()
        if daemon_is_enabled $talker; then
            if [[ -f "$WEBDIR/index.php" ]]; then
                modules=("${modules[@]}" "lcweb")
            else
                echo -e "$STATUS_ERR lcweb is not installed"
            fi
            if [[ -d "$LIVECLOUDWEB/Zend/library/" ]]; then
                modules=("${modules[@]}" "Zend")
            else
                echo -e "$STATUS_ERR $LIVECLOUDWEB/Zend/library is not installed"
            fi
            if [[ -d "$WEBDIR/public/plugin/noVNC/" ]]; then
                modules=("${modules[@]}" "noVNC")
            else
                echo -e "$STATUS_ERR $WEBDIR/public/plugin/noVNC is not installed"
            fi
            if [[ -f "$WEBDIR/.htaccess" ]]; then
                modules=("${modules[@]}" ".htaccess")
            else
                echo -e "$STATUS_ERR $WEBDIR/.htaccess missing"
            fi
            module_str="${modules[@]}"
            if [[ ${#modules[@]} -gt 0 ]]; then
                echo -e "$STATUS_OK ${module_str// /, } is installed"
            fi
        fi
        modules=()
        if daemon_is_enabled $charge; then
            if [[ -f "$BSSDIR/index.php" ]]; then
                modules=("${modules[@]}" "lcweb_bss")
            else
                echo -e "$STATUS_ERR lcweb_bss is not installed"
            fi
            if [[ -d "$LIVECLOUDWEB/Zend/library/" ]]; then
                modules=("${modules[@]}" "Zend")
            else
                echo -e "$STATUS_ERR $LIVECLOUDWEB/Zend/library is not installed"
            fi
            if [[ -f "$BSSDIR/.htaccess" ]]; then
                modules=("${modules[@]}" ".htaccess")
            else
                echo -e "$STATUS_ERR $BSSDIR/.htaccess missing"
            fi
            module_str="${modules[@]}"
            if [[ ${#modules[@]} -gt 0 ]]; then
                echo -e "$STATUS_OK ${module_str// /, } is installed"
            fi
        fi
    elif [[ "$1" = "details" ]]; then
        check_lcweb_status overview
    fi
}

check_idagent_status()
{
    daemon="$BINDIR/id_agent/idagent.py"
    if [[ "$1" = "overview" ]]; then
        overview_daemon_status "$daemon" $idagent
    elif [[ "$1" = "details" ]]; then
        check_daemon_status "$daemon" $idagent
    fi
}

check_keystone_status()
{
    daemon="/usr/bin/keystone-all"
    if [[ "$1" = "overview" ]]; then
        overview_daemon_status "$daemon" $keystone
    elif [[ "$1" = "details" ]]; then
        check_daemon_status "$daemon" $keystone
    fi
}

check_sdncontroller_status()
{
    daemon="$BINDIR/sdncontroller/sdncontroller.py"
    if [[ "$1" = "overview" ]]; then
        overview_daemon_status "$daemon" $sdncontroller
    elif [[ "$1" = "details" ]]; then
        check_daemon_status "$daemon" $sdncontroller
    fi
}

check_exchange_status()
{
    daemon="$BINDIR/exchange/exchange.py"
    if [[ "$1" = "overview" ]]; then
        overview_daemon_status "$daemon" $exchange
    elif [[ "$1" = "details" ]]; then
        check_daemon_status "$daemon" $exchange
    fi
}

check_vmwareadapter_status()
{
    daemon="$LIBDIR/adapter-vmware"
    if [[ "$1" = "overview" ]]; then
        overview_daemon_status "$daemon" $vmwareadapter
    elif [[ "$1" = "details" ]]; then
        check_daemon_status "$daemon" $vmwareadapter
    fi
}

check_yynwadapter_status()
{
    daemon="$BINDIR/yynwadapter/neutronadapter.py"
    if [[ "$1" = "overview" ]]; then
        overview_daemon_status "$daemon" $yynwadapter
    elif [[ "$1" = "details" ]]; then
        check_daemon_status "$daemon" $yynwadapter
    fi
}

check_environment_status()
{
    if [[ "$1" = "overview" ]]; then
        echo -e "\033[30G Environment status"

        if daemon_is_enabled $httpd; then
            info="$STATUS_ENABLE"
            CHECK=`systemctl is-active httpd`
            if [[ $? -ne 0 ]]; then
                echo -e "$info$STATUS_ERR HTTPD:\033[20G `systemctl is-active httpd`"
            else
                echo -e "$info$STATUS_OK HTTPD:\033[20G `systemctl is-active httpd`"
            fi
        else
            info="$STATUS_DISABLE"
        fi
        if daemon_is_enabled $nginx; then
            info="$STATUS_ENABLE"
            CHECK=`systemctl is-active nginx`
            if [[ $? -ne 0 ]]; then
                echo -e "$info$STATUS_ERR NGINX:\033[20G `systemctl is-active nginx`"
            else
                echo -e "$info$STATUS_OK NGINX:\033[20G `systemctl is-active nginx`"
            fi
        else
            info="$STATUS_DISABLE"
        fi

        CHECK=`systemctl is-active mariadb`
        if [[ $? -ne 0 ]]; then
            echo -e "$STATUS_ERR MYSQLD:\033[20G `systemctl is-active mariadb`"
        else
            expversion=`grep -w LC_VERSION $WEBDIR/const.php 2>$- |
                grep -Eo "v[0-9]+_[0-9]+"`
            : ${expversion:=NULL}
            if daemon_is_enabled $talker; then
                dbversion=`mysql livecloud -sNe "SHOW TABLES" |
                    grep -Eo "v[0-9]+_[0-9]+$" | sort | uniq`
                : ${dbversion:=NULL}
                if [[ "$expversion" = "$dbversion" ]]; then
                    echo -e "$STATUS_OK MYSQLD:\033[20G`systemctl is-active mariadb`," \
                        "db version is $dbversion"
                else
                    echo -e "$STATUS_ERR MYSQLD:\033[20G`systemctl is-active mariadb`," \
                        "db version is $dbversion, but lcweb expect $expversion"
                fi
            elif daemon_is_enabled $charge; then
                echo -e "$STATUS_OK MYSQLD:\033[20G`systemctl is-active mariadb`"
            fi
        fi

        CHECK=`systemctl is-active mongod`
        if [[ $? -ne 0 ]]; then
            echo -e "$STATUS_ERR MONGOD:\033[20G `systemctl is-active mongod`"
        else
            echo -e "$STATUS_OK MONGOD:\033[20G `systemctl is-active mongod`"
        fi

        CHECK=`systemctl is-active influxdb`
        if [[ $? -ne 0 ]]; then
            echo -e "$STATUS_ERR InfluxDB:\033[20G `systemctl is-active influxdb`"
        else
            echo -e "$STATUS_OK InfluxDB:\033[20G `systemctl is-active influxdb`"
        fi

        CHECK=`systemctl is-active elasticsearch`
        if [[ $? -ne 0 ]]; then
            echo -e "$STATUS_ERR ElasticSearch:\033[20G `systemctl is-active elasticsearch`"
        else
            echo -e "$STATUS_OK ElasticSearch:\033[20G `systemctl is-active elasticsearch`"
        fi

        CHECK=`systemctl is-active telegraf`
        if [[ $? -ne 0 ]]; then
            echo -e "$STATUS_ERR Telegraf:\033[20G `systemctl is-active telegraf`"
        else
            echo -e "$STATUS_OK Telegraf:\033[20G `systemctl is-active telegraf`"
        fi

        CHECK=`systemctl is-active grafana-server`
        if [[ $? -ne 0 ]]; then
            echo -e "$STATUS_ERR Grafana:\033[20G `systemctl is-active grafana-server`"
        else
            echo -e "$STATUS_OK Grafana:\033[20G `systemctl is-active grafana-server`"
        fi

        CHECK=`systemctl is-active kibana`
        if [[ $? -ne 0 ]]; then
            echo -e "$STATUS_ERR Kibana:\033[20G `systemctl is-active kibana`"
        else
            echo -e "$STATUS_OK Kibana:\033[20G `systemctl is-active kibana`"
        fi

        disk_usage=`df . --direct -h | awk '{
            if (NR==1) {s1=$1; s2=$2; s3=$3; s4=$4; s5=$5}
            else {print s1":"$1, s2":"$2, s3":"$3, s4":"$4, s5":"$5}
        }'`
        disk_used_rate=`echo $disk_usage | grep -Eo "[0-9]+%" | grep -Eo "[0-9]+"`
        if [[ $disk_used_rate -le 60 ]]; then
            echo -e "$STATUS_OK DISK:\033[20G $disk_usage"
        elif [[ $disk_used_rate -le 80 ]]; then
            echo -e "$STATUS_WARN DISK:\033[20G $disk_usage${wrap_warn}>60%${wrap_over}"
        else
            echo -e "$STATUS_ERR DISK:\033[20G $disk_usage${wrap_err}>80%${wrap_over}"
        fi

        local_hostname=`hostname -s`
        CHECK=`rabbitmqctl cluster_status 2>&1 | grep -E "running_nodes[^\n]+livecloud@$local_hostname"`
        if [[ $? -ne 0 ]]; then
            echo -e "$STATUS_ERR RABBITMQ:\033[20G rabbitmq is not running"
        else
            echo -e "$STATUS_OK RABBITMQ:\033[20G$CHECK"
        fi

        ipforward_proc=`cat /proc/sys/net/ipv4/ip_forward`
        if [[ "$ipforward_proc" != "1" ]]; then
            echo -e "$STATUS_ERR FORWARDING:\033[20G /proc/sys/net/ipv4/ip_forward: $ipforward_proc"
        else
            echo -e "$STATUS_OK FORWARDING:\033[20G /proc/sys/net/ipv4/ip_forward: $ipforward_proc"
        fi

        CHECK=`cat /etc/sysctl.d/98-sysctl.conf|grep -e "^[ ]\{0,\}net.ipv4.ip_forward[ ]\{0,\}=[ ]\{0,\}1"`
        if [[ -z "$CHECK" ]]; then
            echo -e "$STATUS_ERR \033[20G /etc/sysctl.conf: $CHECK"
        else
            echo -e "$STATUS_OK \033[20G /etc/sysctl.conf: $CHECK"
        fi
    elif [[ "$1" = "details" ]]; then
        check_environment_status overview
    fi
}

check_iptables_status()
{
    if [[ "$1" = "overview" ]]; then
        IPTABLES_FILTER_RULES=(
            '-A IN_public_allow -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT'
            '-A IN_public_allow -p tcp -m tcp --dport 5666 -m conntrack --ctstate NEW -j ACCEPT'
            '-A IN_public_allow -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT'
			'-A IN_public_allow -p tcp -m tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT'
			'-A IN_public_allow -p tcp -m tcp --dport 4369 -m conntrack --ctstate NEW -j ACCEPT'
			'-A IN_public_allow -p tcp -m tcp --dport 623 -m conntrack --ctstate NEW -j ACCEPT'
			'-A IN_public_allow -p tcp -m tcp --dport 10900:12899 -m conntrack --ctstate NEW -j ACCEPT'
			'-A IN_public_allow -p tcp -m tcp --dport 123 -m conntrack --ctstate NEW -j ACCEPT'
			'-A IN_public_allow -p udp -m udp --dport 20000:20149 -m conntrack --ctstate NEW -j ACCEPT'
			'-A IN_public_allow -p tcp -m tcp --dport 22901:23299 -m conntrack --ctstate NEW -j ACCEPT'
			'-A IN_public_allow -p udp -m udp --dport 161 -m conntrack --ctstate NEW -j ACCEPT'
			'-A IN_public_allow -p tcp -m tcp --dport 20000:20149 -m conntrack --ctstate NEW -j ACCEPT'
			'-A IN_public_allow -p tcp -m tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT'
			'-A IN_public_allow -p tcp -m tcp --dport 20900:22899 -m conntrack --ctstate NEW -j ACCEPT'
			'-A IN_public_allow -p tcp -m tcp --dport 25000:33000 -m conntrack --ctstate NEW -j ACCEPT'
			'-A IN_public_allow -p tcp -m tcp --dport 43003 -m conntrack --ctstate NEW -j ACCEPT'
			'-A IN_public_allow -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT'
        )

        OK=1

        # filter table
        filter=`iptables -S`
        for i in `seq 1 ${#IPTABLES_FILTER_RULES[@]}`; do
            if [[ `echo $filter | grep -c -- "${IPTABLES_FILTER_RULES[$i]}"` -eq 0 ]]; then
                OK=0
                echo -e "$STATUS_ERR IPTABLES: \033[20G" \
                    "Rule '${IPTABLES_FILTER_RULES[$i]}' not found" >&2
                return 1
            fi
        done
        if [[ "$OK" -eq 1 ]]; then
            echo -e "$STATUS_OK IPTABLES \033[20G ${#IPTABLES_FILTER_RULES[@]} rules in use."
        fi
    elif [[ "$1" = "details" ]]; then
        echo "iptables:"
        echo "filter"
        iptables -S -t filter

        echo "nat"
        iptables -S -t nat

        echo "mangle"
        iptables -S -t mangle

        echo ""
        echo "Route:"
        route -n

        echo ""
        echo "Policy Route:"
        ip rule list

        echo ""
        echo "IP Address:"
        ifarray=(`ifconfig | cut -d " " -f 1 | xargs echo`)
        for oneif in ${ifarray[@]}; do
            echo -e "$oneif \t`ifconfig $oneif | grep  'inet addr:' | cut -d: -f2 | awk '{ print $1}'`"
        done
    fi
}

check_vm_template_status()
{
    if daemon_is_enabled $talker; then
        if [[ "$1" = "overview" ]]; then
            CHECK=`$MT template.list --minimal | grep -o '[^,]' | wc -l`
            if [[ "$CHECK" -eq 0 ]]; then
                echo -e "$STATUS_ERR No available VM template. \033[20G" >&2
            else
                echo -e "$STATUS_OK VM Templates \033[20G $CHECK template(s) available."
            fi
        elif [[ "$1" = "details" ]]; then
            $MT template.list
        fi
    fi
}

check_host_storage_status()
{
    if daemon_is_enabled $talker; then
        if [[ "$1" = "overview" ]]; then
            cmd="SELECT ip FROM host_device_v$DBVER WHERE ip NOT IN \
                (SELECT host_address FROM storage_connection_v$DBVER WHERE active IS NOT NULL) \
                AND type<>3;"
            hosts=(`$DBEXEC "$cmd"`)
            if [[ "${#hosts[@]}" -ne 0 ]]; then
                echo -e "$STATUS_ERR Storage of ${#hosts[@]} host(s) not activated. \033[20G" >&2
            else
                echo -e "$STATUS_OK All host storage activated\033[20G"
            fi
        elif [[ "$1" = "details" ]]; then
            $MT storage.list
        fi
    fi
}

check_peer_ha_status()
{
    PEERS=(`$DBEXEC "SELECT ip FROM compute_resource_v$DBVER
        WHERE service_flag=1" 2>$-`)
    ret=0

    TIMEOUT_SSH="timeout -t 3 ssh"
    BEACONS=""
    for pip in ${PEERS[@]}; do
        if [[ -z "$LCC_IP" ]]; then
            LCC_IP=`ping $pip -R -c 1 | grep "^RR:" | awk '{print $2}'`
        fi
        pip_exec="$TIMEOUT_SSH root@$pip"

        # check peer node

        pname=`$TIMEOUT_SSH -q -o PasswordAuthentication=no root@$pip hostname 2>&1`
        rc=$?
        if [[ $rc -ne 0 ]]; then
            echo -e "$STATUS_ERR PEER-HA:\033[20G can not login $pip from $LCC_IP using GSSAPI"
            ret=1
        else
            CHECK=`$pip_exec ssh -q -o PasswordAuthentication=no root@$LCC_IP hostname 2>&1`
            rc=$?
            if [[ $rc -ne 0 ]]; then
                echo -e "$STATUS_ERR PEER-HA:\033[20G can not login $LCC_IP from $pip using GSSAPI"
                ret=1
            fi

            CHECK=`$pip_exec service drbd status 2>&1`
            rc=$?
            if [[ $rc -ne 0 ]]; then
                echo -e "$STATUS_ERR PEER-HA:\033[20G drbd is not running on $pip"
                ret=1
            fi
            CHECK=`$pip_exec service corosync status 2>&1`
            rc=$?
            if [[ $rc -ne 0 ]]; then
                echo -e "$STATUS_ERR PEER-HA:\033[20G corosync is not running on $pip"
                ret=1
            fi

            CHECK=`$pip_exec drbdadm role res-$pname 2>&1`
            rc=$?
            if [[ $rc -ne 0 || "$CHECK" != Primary/* ]]; then
                echo -e "$STATUS_ERR PEER-HA:\033[20G drbd resource res-$pname on $pip is not Primary"
                ret=1
            else
                echo -e "$STATUS_OK PEER-HA:\033[20G drbd resource res-$pname on $pip is Primary"

                CHECK=`$pip_exec crm resource status drbd-$pname 2>&1 |
                    grep -E " is running on: $pname Master"`
                rc=$?
                if [[ $rc -ne 0 ]]; then
                    echo -e "$STATUS_ERR PEER-HA:\033[20G drbd pacemaker resource drbd-$pname on $pip is not Master"
                    ret=1
                else
                    echo -e "$STATUS_OK PEER-HA:\033[20G drbd pacemaker resource drbd-$pname on $pip is Master"
                fi
                CHECK=`$pip_exec crm resource status pbd-$pname 2>&1 |
                    grep -E " is running on: $pname "`
                rc=$?
                if [[ $rc -ne 0 ]]; then
                    echo -e "$STATUS_ERR PEER-HA:\033[20G pbd pacemaker resource pbd-$pname on $pip is not running"
                    ret=1
                else
                    echo -e "$STATUS_OK PEER-HA:\033[20G pbd pacemaker resource pbd-$pname on $pip is running"
                fi
            fi
        fi

        # check beacon node

        beacon=`$DBEXEC "SELECT a.ip FROM pacemaker_beacon_v$DBVER AS a
            WHERE EXISTS (SELECT *
                FROM compute_resource_v$DBVER AS b, compute_resource_v$DBVER AS c
                WHERE a.ip=b.ip AND b.rackid=c.rackid AND c.ip='$pip')" 2>$-`
        if [[ -z "$beacon" ]]; then
            echo -e "$STATUS_ERR PEER-HA:\033[20G can not find the beacon of $pip"
            ret=1
            continue
        fi
        if echo "$BEACONS" | grep -qs " $beacon "; then
            continue
        fi
        BEACONS="$BEACONS $beacon "
        beacon_passwd=`$DBEXEC "SELECT user_passwd
            FROM compute_resource_v$DBVER WHERE ip='$beacon'" 2>$-`
        if [[ -z "$beacon" ]]; then
            echo -e "$STATUS_ERR PEER-HA:\033[20G the beacon of $pip ($beacon) does not join any resource pool"
            ret=1
            continue
        fi

        beacon_exec="$TIMEOUT_SSH root@$beacon"
        CHECK=`$TIMEOUT_SSH -q -o PasswordAuthentication=no root@$beacon hostname 2>&1`
        rc=$?
        if [[ $rc -ne 0 ]]; then
            echo -e "$STATUS_ERR PEER-HA:\033[20G can not login the beacon of $pip ($beacon) from $LCC_IP using GSSAPI"
            ret=1
        else
            CHECK=`$beacon_exec ssh -q -o PasswordAuthentication=no root@$LCC_IP hostname 2>&1`
            rc=$?
            if [[ $rc -ne 0 ]]; then
                echo -e "$STATUS_ERR PEER-HA:\033[20G can not login $LCC_IP from the beacon of $pip ($beacon) using GSSAPI"
                ret=1
            fi
            CHECK=`$beacon_exec service corosync status 2>&1`
            rc=$?
            if [[ $rc -ne 0 ]]; then
                echo -e "$STATUS_ERR PEER-HA:\033[20G corosync is not running on the beacon of $pip ($beacon)"
                ret=1
            else
                echo -e "$STATUS_OK PEER-HA:\033[20G the beacon of $pip is $beacon"
            fi
        fi
    done

    return $ret
}

check_resource_status()
{
    ret=0

    echo -e "\033[30G Resource Status"
    check_peer_ha_status
    rc=$?
    if [[ $rc -ne 0 ]]; then
        ret=$rc
    fi

    # TODO check other resources

    return $ret
}

check_cobbler_status()
{
    if daemon_is_disabled $cobbler; then
        return
    fi
    cobbler_servers=(`$SQLEXEC "SELECT ip FROM $PXE_DEVICE_TABLE;"`)
    if [[ ${#cobbler_servers[@]} -eq 0 ]]; then
        state="COBBLER: servers not setup"
        echo -e "$STATUS_DISABLE$STATUS_DOWN $state" >&2
        return
    fi
    for cobbler_server in ${cobbler_servers[@]}; do
        cobbler_user_info=(`$SQLEXEC "SELECT user_name,user_passwd FROM $PXE_DEVICE_TABLE
            WHERE ip='$cobbler_server';"`)
        cobbler_user_name=${cobbler_user_info[0]}
        cobbler_user_passwd=${cobbler_user_info[1]}
        CHECK=`sshpass -p $cobbler_user_passwd $SSH $cobbler_user_name@$cobbler_server \
            ps ax | grep -w "cobblerd" | grep -v grep | awk '{print $1}'`
        if [[ -z "$CHECK" ]]; then
            state="COBBLER: $cobbler_server cobblerd not running..."
            echo -e "$STATUS_ENABLE$STATUS_DOWN $state" >&2
        else
            state="COBBLER: $cobbler_server cobblerd (pid $CHECK) is running..."
            echo -e "$STATUS_ENABLE$STATUS_RUNNING $state"
        fi
    done
}

process_ps()
{
    ps aux | grep -E "$1" | grep -Ewv "grep|start|stop|restart"
}

start_daemon()
{
    daemon="$1"
    status="$2"
    shift 2
    cmd="$@"
    if daemon_is_enabled $status; then
        CHECK=`process_ps $daemon`
        if [[ -z "$CHECK" ]]; then
            CHK=`eval "$cmd"`
            if [[ "$daemon" == "resource-job" ]]; then
                sleep 6
            fi
            # Daemon can be running at start, at this time check may pass,
            # but after listen port bind failed, daemon will actually exit,
            # therefore, do sleep to ensure that check is valid.
            sleep 1
            CHECK=`process_ps $daemon`
            if [[ -z "$CHECK" ]]; then
                echo true
                return 1
            fi
        fi
    fi
    echo false
    return 0
}

__stop_daemon()
{
    daemon="$1"
    shift 1
    cmd="$@"
    CHK=`eval "$cmd"`
    sleep $TIMEVAL
    CHECK=`process_ps $daemon`
    if [[ -n "$CHECK" ]]; then
        echo true
        return 1
    fi
    echo false
    return 0
}

stop_daemon()
{
    daemon="$1"
    type="$2"
    case $type in
        1)
            cmd="pkill -9 $daemon"
            ;;
        2)
            cmd="pkill -TERM $daemon; sleep 2; killall -9 $daemon 2>$-"
            ;;
        *)
            cmd="process_ps $daemon | awk '{print \$2}' | xargs kill -9 2>$-"
            ;;
    esac
    __stop_daemon $daemon "$cmd"
}

start_service()
{
    typeset __err
    daemon="$1"
    status="$2"
    shift 2
    cmd="$@"
    if daemon_is_enabled $status; then
        CHECK=`process_ps $daemon`
        if [[ -z "$CHECK" ]]; then
            if [[ -n "$cmd" ]]; then
                CHK=`eval "$cmd"`
            fi
            CHK=`service $daemon restart 2>&1`
            __err=$?
            if [[ "$daemon" == "mysql" ]]; then
                CHK=`service $daemon restart 2>&1`
                __err=$?
            fi
            if [[ $__err -ne 0 ]]; then
                echo true
                return 1
            fi
        fi
    fi
    echo false
    return 0
}

stop_service()
{
    daemon="$1"
    CHK=`service $daemon stop 2>&1`
    if [[ $? -ne 0 ]]; then
        echo true
        return 1
    fi
    echo false
    return 0
}

start_lcrmd()
{
    daemon="lcrmd"
    cmd="$BINDIR/lcrmd -l 7 -d -t 8 2>&1"
    start_daemon $daemon $lcrmd "$cmd"
}

stop_lcrmd()
{
    daemon="lcrmd"
    stop_daemon $daemon 1
}

start_vmdriver()
{
    daemon="vmdriver"
    cmd="$BINDIR/vmdriver -l 7 -d -t 8 2>&1"
    start_daemon $daemon $vmdriver "$cmd"
}

stop_vmdriver()
{
    daemon="vmdriver"
    stop_daemon $daemon 1
}

start_lcpd()
{
    daemon="lcpd"
    cmd="$BINDIR/lcpd -l 7 -d -t 8 2>&1"
    start_daemon $daemon $lcpd "$cmd"
}

stop_lcpd()
{
    daemon="lcpd"
    stop_daemon $daemon 1
}

start_lcmond()
{
    daemon="lcmond"
    cmd="$BINDIR/lcmond -l 7 -d -t 8 2>&1"
    start_daemon $daemon $lcmond "$cmd"
}

stop_lcmond()
{
    daemon="lcmond"
    stop_daemon $daemon 2
}

start_lcsnfd()
{
    daemon="lcsnfd"
    cmd="$BINDIR/lcsnfd -l 7 -d 2>&1"
    start_daemon $daemon $lcsnfd "$cmd"
}

stop_lcsnfd()
{
    daemon="lcsnfd"
    stop_daemon $daemon 2
}

start_postman()
{
    daemon="postman"
    cmd="$BINDIR/postman/postman.py"
    start_daemon $daemon $postman "$cmd"
}

stop_postman()
{
    daemon="postman"
    stop_daemon $daemon
}

start_talker()
{
    daemon="talker"
    cmd="$BINDIR/talker/talker.py -d"
    start_daemon $daemon $talker "$cmd"
}

stop_talker()
{
    daemon="talker"
    stop_daemon $daemon
    if [[ "$1" == "--force" ]]; then
        while :; do
            processes=`get_process_by_listen_port 20013`
            if [[ -z "$processes" ]]; then
                break
            fi
            echo -e "$OK" >&2
            echo "  WARNING: The following processes are using the tcp port 20013," >&2
            for _process in $processes; do
                echo "           `ps -p $_process o pid,cmd 2>$- | grep -wv CMD`" >&2
            done
            echo -n "  WILL you force to kill them (Y/n): " >&2
            read key
            case $key in
                Y | [Yy][Ee][Ss])
                    echo -n "  Killing ... " >&2
                    echo $processes | sed 's/ /\n/g' | xargs kill -9 2>$-
                    ;;
                *)
                    echo -n "  Skiping ... " >&2
                    break
                    ;;
            esac
        done
    fi
}

start_storekeeper()
{
    daemon="storekeeper"
    cmd="$BINDIR/storekeeper/storekeeper.py -d"
    start_daemon $daemon $storekeeper "$cmd"
}

stop_storekeeper()
{
    daemon="storekeeper"
    stop_daemon $daemon
}

start_cashier()
{
    daemon="cashier"
    cmd="$BINDIR/cashier/cashier.py -d"
    start_daemon $daemon $cashier "$cmd"
}

stop_cashier()
{
    daemon="cashier"
    stop_daemon $daemon
}

start_backup()
{
    daemon="backup"
    cmd="$BINDIR/backup/backup.py -d"
    start_daemon $daemon $backup "$cmd"
}

stop_backup()
{
    daemon="backup"
    stop_daemon $daemon
}

start_painter()
{
    daemon="painter"
    cmd="$BINDIR/painter/painter.py -d"
    start_daemon $daemon $painter "$cmd"
}

stop_painter()
{
    daemon="painter"
    stop_daemon $daemon
}

start_analyzer()
{
    daemon="analyzer"
    cmd="$BINDIR/analyzer/analyzer.py -d"
    start_daemon $daemon $analyzer "$cmd"
}

stop_analyzer()
{
    daemon="analyzer"
    stop_daemon $daemon
}

start_resourcejob()
{
    daemon="resource-job"
    cmd="cd /; nohup sh $RESOURCE_JOB_SCRIPT start >> $LIVECLOUDLOG/resource-job-adapter.log 2>&1 &"
    start_daemon $daemon $resourcejob "$cmd"
}

stop_resourcejob()
{
    daemon="resource-job"
    stop_daemon $daemon
}

start_charge()
{
    daemon="charge"
    cmd="cd $BINDIR/charge; node charge.js >> $LIVECLOUDLOG/charge.log 2>&1 &"
    start_daemon $daemon $charge "$cmd"
}

stop_charge()
{
    daemon="charge"
    stop_daemon $daemon
}

start_lcwebapi()
{
    daemon="app"
    cmd="cd $BINDIR/lcwebapi; node app.js >> $LIVECLOUDLOG/lcwebapi.log 2>&1 &"
    start_daemon $daemon $lcwebapi "$cmd"
}

stop_lcwebapi()
{
    daemon="app"
    stop_daemon $daemon
}

start_nodelistener()
{
    daemon="msgCenterlistener"
    cmd="cd $BINDIR/lcwebapi; node msgCenterlistener.js >> $LIVECLOUDLOG/statesniffer_listener.log 2>&1 &"
    start_daemon $daemon $nodelistener "$cmd"
}

stop_nodelistener()
{
    daemon="msgCenterlistener"
    stop_daemon $daemon
}

start_idagent()
{
    daemon="idagent"
    cmd="/usr/bin/python $BINDIR/id_agent/idagent.py"
    start_daemon $daemon $idagent "$cmd"
}

stop_idagent()
{
    daemon="idagent"
    stop_daemon $daemon
}

start_keystone()
{
    daemon="keystone-all"
    cmd="keystone-all >> $LIVECLOUDLOG/keystone.log 2>&1 &"
    start_daemon $daemon $keystone "$cmd"
}

stop_keystone()
{
    daemon="keystone-all"
    stop_daemon $daemon
}

start_sdncontroller()
{
    daemon="sdncontroller"
    cmd="$BINDIR/sdncontroller/sdncontroller.py -d"
    start_daemon $daemon $sdncontroller "$cmd"
}

stop_sdncontroller()
{
    daemon="sdncontroller"
    stop_daemon $daemon
}

start_exchange()
{
    daemon="exchange"
    cmd="$BINDIR/exchange/exchange.py -d"
    start_daemon $daemon $exchange "$cmd"
}

stop_exchange()
{
    daemon="exchange"
    stop_daemon $daemon
}

start_vmwareadapter()
{
    daemon="adapter-vmware"
    cmd="cd /; nohup sh $VMWARE_ADAPTER_SCRIPT start >> $LIVECLOUDLOG/adapter-vmware.log 2>&1 &"
    start_daemon $daemon $vmwareadapter "$cmd"
}

stop_vmwareadapter()
{
    daemon="adapter-vmware"
    stop_daemon $daemon
}

start_yynwadapter()
{
    daemon="neutronadapter"
    cmd="/usr/bin/python $BINDIR/yynwadapter/neutronadapter.py -d"
    start_daemon $daemon $yynwadapter "$cmd"
}

stop_yynwadapter()
{
    daemon="neutronadapter"
    stop_daemon $daemon
}

start_environment()
{
    typeset __err
    ulimit -c unlimited
    ulimit -s $STACK_SIZE
    CHECK=`process_ps "xe .* vm-install template"`
    if [[ -n "$CHECK" ]]; then
        echo
    fi
    while [[ -n "$CHECK" ]]; do
        sleep 1
        echo -e -n "\rwaitting xe vm-install process to terminate .   "
        sleep 1
        echo -e -n "\rwaitting xe vm-install process to terminate ..  "
        sleep 1
        echo -e -n "\rwaitting xe vm-install process to terminate ... "
        CHECK=`process_ps "xe .* vm-install template"`
    done

    __err=false
    __ret=0
    if `start_rabbitmq_server`; then
        __err=true
        __ret=1
    fi
    if `start_mysql`; then
        __err=true
        __ret=1
    fi
    if `start_mongod`; then
        __err=true
        __ret=1
    fi
    if `start_httpd`; then
        __err=true
        __ret=1
    fi
    if `start_nginx`; then
        __err=true
        __ret=1
    fi
    echo $__err
    return $__ret
}

stop_environment()
{
    typeset __err
    __err=false
    __ret=0
    CHECK=`process_ps "bash $WEBDIR/public/plugin/noVNC/utils/launch.sh --vnc"`
    if [[ -n "$CHECK" ]]; then
        echo "$CHECK" | awk '{print $2}' | xargs kill -9 2>$-
        sleep $TIMEVAL
        CHECK=`process_ps "bash $WEBDIR/public/plugin/noVNC/utils/launch.sh --vnc"`
        if [[ -n "$CHECK" ]]; then
            __err=true
            __ret=1
        fi
    fi
    CHECK=`process_ps "sshpass -p zzzzzzzzzzz ssh"`
    if [[ -n "$CHECK" ]]; then
        echo "$CHECK" | awk '{print $2}' | xargs kill -9 2>$-
        sleep $TIMEVAL
        CHECK=`process_ps "sshpass -p zzzzzzzzzzz ssh"`
        if [[ -n "$CHECK" ]]; then
            __err=true
            __ret=1
        fi
    fi
    echo $__err
    return $__ret
}

start_rabbitmq_server()
{
    service="rabbitmq-server"
    start_service $service $status_true
}

stop_rabbitmq_server()
{
    service="rabbitmq-server"
    stop_service $service
}

start_mysql()
{
    service="mysql"
    start_service $service $status_true
}

stop_mysql()
{
    service="mysql"
    mysql_pids=(`ps ax | grep -w "$service" | grep -v grep | awk '{print $1}'`)
    for mysql_pid in ${mysql_pids[@]}; do
        kill -9 $mysql_pid 2>$-
    done
    stop_service $service
}

start_mongod()
{
    service="mongod"
    cmd="rm -f /var/lib/mongo/mongod.lock 2>&1"
    start_service $service $status_true "$cmd"
}

stop_mongod()
{
    service="mongod"
    stop_service $service
}

start_httpd()
{
    service="httpd"
    start_service $service $httpd
}

stop_httpd()
{
    service="httpd"
    stop_service $service
}

start_nginx()
{
    service="nginx"
    start_service $service $nginx
}

stop_nginx()
{
    service="nginx"
    stop_service $service
}

start_cobbler()
{
    echo false
    return 0
}

stop_cobbler()
{
    echo false
    return 0
}

__wait_db_start()
{
    typeset __try __err
    __try=0
    __err=0
    while [[ $__try -lt 10 ]]; do
        sleep 3
        mongo localhost:20011 --eval "db.getName()" >$- 2>&1
        (( __err += $? ))
        $DBEXEC "SHOW TABLES;" >$- 2>&1
        (( __err += $? ))
        if [[ $__err -eq 0 ]]; then
            echo false
            return 0
        fi
        (( __try += 1 ))
    done
    echo true
    return 1
}

usage()
{
    echo -e "Usage:\tlivecloud [ status | start | stop | restart | refresh | cluster ] [ daemon ]"
    echo -e "Options:"
    echo -e "      \tstatus  - show current status of 2Cloud daemones"
    echo -e "      \tstart   - run 2Cloud daemons"
    echo -e "      \tstop    - shutdown 2Cloud daemons"
    echo -e "      \trestart - reload 2Cloud daemons"
    echo -e "      \trefresh - restart services of rsyslog, mysql, httpd and nginx"
    echo -e "      \t          and re-initilize 2Cloud database"
    echo -e "      \tcluster - config 2Cloud cluster"
    echo -e "Optional Parameters:"
    echo -e "      \tdaemon  - daemons for option status/start/stop/restart include:"
    echo -e "      \t          $STR_DAEMONS"
    exit 0
}

# Note that the order of module name determines the order of status display
MODULES=(lcrmd vmdriver lcpd lcmond lcsnfd postman talker storekeeper cashier
         backup painter sdncontroller analyzer idagent exchange yynwadapter
         vmwareadapter resourcejob charge lcwebapi nodelistener cobbler lcweb
         environment iptables vm_template host_storage keystone)

module_exist()
{
    __module=$1
    type=$2
    if [[ "$type" == "status" ]]; then
        for _module in ${MODULES[@]}; do
            if [[ "$_module" == "$__module" ]]; then
                echo true
                return 1
            fi
        done
    else
        for _module in environment ${DAEMONS[@]}; do
            if [[ "$_module" == "$__module" ]]; then
                echo true
                return 1
            fi
        done
    fi
    echo false
    return 0
}

livecloud_status()
{
    __module=$2
    config_parse
    if [[ -z "$__module" ]]; then
        echo -e "\033[30G Module Status"
        for _module in ${MODULES[@]}; do
            eval check_${_module}_status overview
        done
        echo
        echo -e "$MANUAL_CHECK: you can use \`livecloud status resource\` to see resource status."
    else
        if `module_exist $__module status`; then
            eval check_${__module}_status details
        else
            echo "$ERROR: module $__module does not exist"
            exit 1
        fi
    fi

    exit $?
}

livecloud_start()
{
    __module=$2
    err=false
    config_parse
    if [[ -z "$__module" ]]; then
        echo -n "Starting livecloud:"
        for _module in environment; do
            if `eval start_$_module`; then
                err=true
            fi
        done
        if `__wait_db_start`; then
            err=true
        fi
        for _module in ${DAEMONS[@]}; do
            if `eval start_$_module`; then
                err=true
            fi
        done
        if $err; then
            echo -e $FAILED
            return 1
        else
            set_db_system_state
            echo -e $OK
            return 0
        fi
    else
        if `module_exist $__module`; then
            echo -n "Starting $__module:"
            err=`eval start_$__module`
            if [[ $? -ne 0 ]]; then
                echo -e $FAILED
                return 1
            else
                echo -e $OK
                return 0
            fi
        else
            echo "$ERROR: module $__module does not exist"
            exit 1
        fi
    fi
}

livecloud_stop()
{
    __module=$2
    err=false
    if [[ -z "$__module" ]]; then
        echo -n "Stopping livecloud:"
        for _module in environment ${DAEMONS[@]}; do
            if `eval stop_$_module`; then
                err=true
            fi
        done
        if $err; then
            echo -e $FAILED
            return 1
        else
            echo -e $OK
            return 0
        fi
    else
        if `module_exist $__module`; then
            echo -n "Stopping $__module:"
            err=`eval stop_$__module $3`
            if [[ $? -ne 0 ]]; then
                echo -e $FAILED
                return 1
            else
                echo -e $OK
                return 0
            fi
        else
            echo "$ERROR: module $__module does not exist"
            exit 1
        fi
    fi
}

livecloud_restart()
{
    __module=$2
    livecloud_stop $*
    if [[ -z "$__module" || "$__module" == "environment" ]]; then
        services=(nginx httpd mongod mysql rabbitmq_server)
        for _service in ${services[@]}; do
            err=`eval stop_$_service`
        done
    fi
    livecloud_start $*
}

livecloud_refresh()
{
    config_parse
    DBPASSWD=""
    while :; do
        echo -n "Please input the password of mysql database: "
        read -s line
        echo
        if [[ -z "$line" ]]; then
            echo 'aborted'
            exit
        fi
        mysql -uadmin -p$line -e ";"  >/dev/null 2>&1
        if [[ $? -ne 0 ]]; then
            echo  "Password error"
            continue
        fi
        DBPASSWD=$line
        break
    done

    systemctl stop mariadb
    sleep 10
    systemctl start mariadb
    sleep 2
    service httpd stop
    if daemon_is_enabled $httpd; then
        service httpd start
    fi
    service nginx stop
    if daemon_is_enabled $nginx; then
        service nginx start
    fi
    service rabbitmq-server restart
    DOMAIN=""
    LCMIP=""
    CHK_DB=`mysql -uadmin -p$DBPASSWD -sNe "show databases;" 2>&1 | grep -w "livecloud"`
    if [[ "$2" = "lcc" ]] && [[ -n "$CHK_DB" ]]; then
        DOMAIN=`$DBEXEC \
            "SELECT value FROM sys_configuration_v$DBVER WHERE param_name='domain'" 2>&1 | tail -n 1`
        LCMIP=`$DBEXEC \
            "SELECT value FROM sys_configuration_v$DBVER WHERE param_name='lcm_ip'" 2>&1 | tail -n 1`
        RUNMODE=`$DBEXEC \
            "SELECT value FROM sys_configuration_v$DBVER WHERE param_name='running_mode'" 2>&1 | tail -n 1`
    else
        DOMAIN=`echo $RANDOM | md5sum | cut -c1-8`
        LCMIP=""
        RUNMODE="independent"
    fi
    CHK=`mysql -uadmin -p$DBPASSWD < $LIVECLOUD/conf/sql_init_cmd >/dev/null 2>&1`
    source $SCRIPTDIR/db.sh
    echo -n "Loading database:"
    err=false
    $DBEXEC "UPDATE sys_configuration_v$DBVER SET value=\"$DOMAIN\" WHERE param_name='domain'" \
        >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        err=true
    fi
    $DBEXEC "UPDATE sys_configuration_v$DBVER SET value=\"$LCMIP\" WHERE param_name='lcm_ip'" \
        >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        err=true
    fi
    $DBEXEC "UPDATE sys_configuration_v$DBVER SET value=\"$RUNMODE\" WHERE param_name='running_mode'" \
        >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        err=true
    fi
    if $err; then
        echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
        exit 1
    else
        echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
    fi
    # stop keystone
    process_ps keystone-all | awk '{print $2}' | xargs kill -9 2>$-
    sleep $TIMEVAL
    # init keystone db
    rm -f /tmp/bss.sql.tmp
    if [[ -f "/usr/bin/keystone-all" ]]; then
        cat << STRING >> /tmp/bss.sql.tmp
drop database if exists keystone;
create database keystone;
grant all on keystone.* to 'keystone'@'localhost' identified by 'livecloud';
STRING
        mysql -uroot -p$DBPASSWD < /tmp/bss.sql.tmp
        rm -f /tmp/bss.sql.tmp
        echo -n "keystone database sync ... "
        keystone-manage db_sync >>/dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            echo -e '\033[60G[  \033[0;32mOK\033[0m  ]'
        else
            echo -e '\033[60G[\033[0;31mFAILED\033[0m]'
        fi
    fi

    if daemon_is_enabled $yynwadapter; then
        yn=`while true; do
            read -p "refresh yyadapter database ?[Y/N]" yn
            case $yn in
                "Y") echo $yn; break;;
                "N") echo $yn; break;;
                *) echo "please input Y or N";;
            esac
        done`
        if [[ "$yn" = 'Y' ]]; then
            `mysql -uadmin -p$DBPASSWD < $LIVECLOUD/bin/yynwadapter/mysql_database_init.sql >/dev/null 2>&1`
        fi
    fi

    echo "Restart livecloud to synchronise memory with db:"
    $0 restart

    echo "generating 1000 initial identifycode at backend"
    nohup curl -X GET -k http://127.0.0.1/identifycode/generate >/dev/null 2>&1 &

    exit $?
}

livecloud_cluster()
{
    if [[ $# -lt 5 ]]; then
        echo "Usage: $0 $1 <ip-1> <pw-1> <ip-2> <pw-2> [ <ip-3> <pw-3> ... ]"
        echo "  cluster livebus in <ip-1>, <ip-2>, ..., and launch livecloud in <ip-1>"
        exit 1
    fi
    shift
    ip_pw_list=($@)
    local_ssh='sshpass -p $local_pw ssh root@$local_ip'

    # stop livecloud and rabbitmq
    livecloud stop
    rabbitmqctl stop
    for ((i=2; i<${#ip_pw_list[@]}; i+=2)); do
        ((i1=i+1))
        local_ip=${ip_pw_list[$i]}
        local_pw=${ip_pw_list[$i1]}
        eval $local_ssh livecloud stop 2>$-
        eval $local_ssh rabbitmqctl stop
    done

    # hostnames
    declare -a ip_hn_list
    for ((i=0; i<${#ip_pw_list[@]}; i+=2)); do
        ((i1=i+1))
        local_ip=${ip_pw_list[$i]}
        local_pw=${ip_pw_list[$i1]}
        local_hostname=`eval $local_ssh hostname -s 2>$-`
        ip_hn_list[$i]=$local_ip
        ip_hn_list[$i1]=$local_hostname
    done

    for ((i=0; i<${#ip_pw_list[@]}; i+=2)); do
        ((i1=i+1))
        local_ip=${ip_pw_list[$i]}
        local_pw=${ip_pw_list[$i1]}
        for ((j=0; j<${#ip_hn_list[@]}; j+=2)); do
            ((j1=j+1))
            peer_ip=${ip_hn_list[$j]}
            peer_hostname=${ip_hn_list[$j1]}
            if [[ $i -eq $j ]]; then
                eval $local_ssh "sed -i \"/^127.0.0.1 $peer_hostname$/d\" /etc/hosts" 2>$-
                eval $local_ssh "sed -i \"/^::1 $peer_hostname$/d\" /etc/hosts" 2>$-
            fi
            eval $local_ssh "sed -i \"/^$peer_ip $peer_hostname$/d\" /etc/hosts" 2>$-
            eval $local_ssh "echo -e \"$peer_ip $peer_hostname\" >> /etc/hosts" 2>$-
        done
    done

    # rabbitmq cookie
    for ((i=2; i<${#ip_pw_list[@]}; i+=2)); do
        local_ip=${ip_pw_list[$i]}
        local_pw=${ip_pw_list[$i1]}
        eval $local_ssh "cp /var/lib/rabbitmq/.erlang.cookie /tmp/.erlang.cookie.bak" 2>$-
        sshpass -p $local_pw scp /var/lib/rabbitmq/.erlang.cookie root@$local_ip:/var/lib/rabbitmq/ 2>$-
    done

    # rabbitmq
    rabbitmq-server -detached
    master_hostname=${ip_hn_list[1]}
    for ((i=2; i<${#ip_pw_list[@]}; i+=2)); do
        ((i1=i+1))
        local_ip=${ip_pw_list[$i]}
        local_pw=${ip_pw_list[$i1]}
        eval $local_ssh "rabbitmq-server -detached"
        eval $local_ssh "rabbitmqctl stop_app"
        eval $local_ssh "rabbitmqctl join_cluster livecloud@$master_hostname"
        eval $local_ssh "rabbitmqctl start_app"
    done

    echo "$DONE finish to cluster livecloud, please check cluster status:"
    rabbitmqctl cluster_status
    for ((i=2; i<${#ip_pw_list[@]}; i+=2)); do
        ((i1=i+1))
        local_ip=${ip_pw_list[$i]}
        local_pw=${ip_pw_list[$i1]}
        eval $local_ssh rabbitmqctl cluster_status
    done

    # start livecloud in all node
    livecloud start
    for ((i=2; i<${#ip_pw_list[@]}; i+=2)); do
        ((i1=i+1))
        local_ip=${ip_pw_list[$i]}
        local_pw=${ip_pw_list[$i1]}
        eval $local_ssh livecloud start 2>$-
    done

    exit 0
}

opt=$1
case $opt in
    status)
        livecloud_status $*
        ;;
    start)
        livecloud_start $*
        ;;
    stop)
        livecloud_stop $*
        ;;
    restart)
        livecloud_restart $*
        ;;
    refresh)
        livecloud_refresh
        ;;
    cluster)
        livecloud_cluster $*
        ;;
    *)
        usage
        ;;
esac
exit 0
