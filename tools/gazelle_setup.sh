#!/bin/bash
#Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
#Description: Prepare the environment for gazelle and start the ltran process!

PROJ_ROOT=$(
    cd $(dirname $0)/
    pwd
)
source $PROJ_ROOT/gazelle_common.sh
crontab_cmd=$PROJ_ROOT/gazelle_crontab.sh

# input global args
g_conn_if=""
g_hugepages=""
g_daemon_mod=""
g_kni_switch=""
g_low_power=""
g_ltrancore=""
g_lstackcore=""
g_wakeupcpus=""
g_useltran=""
g_listen_shadow=""

cur_user=""
cur_group=""

# os arch
uname_M=$(uname -m 2> /dev/null || echo not)

function __rm {
    sudo rm -rf $@
}

function __chown {
    sudo chown -R ${cur_user}:${cur_group} $@
}

function __mkdir {
    if [ -d $@ ]; then
        msg_show $@ "existed."
    else
        sudo mkdir -p $@
    fi
    __chown $@
}

function __sysctl {
    sudo sysctl -w "$@"
}

function __ifconfig {
    sudo ifconfig $@
}

function die {
    msg_err "$@"
    exit 1
}

show_usage() {
    echo "Usage: $0 {-h|--help}"
    echo "       $0 {-i=<nic name>|--nic=<nic name>}"
    echo "          [-n|--numa=<numa mem (M)(lstack)>]"
    echo "          [-d|--daemon=<daemon mode>]"
    echo "          [-k|--kni=<kni switch>]"
    echo "          [-l|--lowpower=<low power mode>]"
    echo "          [--ltrancore=<ltran core>]"
    echo "          [--lstackcore=<ltran core>]"
    echo "          [--useltran=<use ltran>]"
    echo "          [--listenshadow=<listen shadow>]"
    echo "examples:"
    echo "       $0 -i eth0 -n 1024,1024 -d 1/0 -k 1/0 -l 1/0 --ltrancore 0,1 --lstackcore 2-3 --useltran 0/1 --listenshadow 0/1"
}

check_init() {
    msg_show "starting check the dependence..."
    local ret=0
    check_dependence numactl
    ret=$(($? + ret))
    check_dependence libpcap
    ret=$(($? + ret))
    check_dependence libconfig
    ret=$(($? + ret))
    check_dependence libsecurec
    ret=$(($? + ret))
    check_dependence pciutils
    ret=$(($? + ret))
    check_dependence gazelle
    ret=$(($? + ret))
    check_dependence dpdk
    ret=$(($? + ret))

    if [ $ret -eq 0 ]; then
        msg_show "check & init devDependencies succeeded!"
    else
        msg_err "check devDependencies failed! please check it yourself!"
        exit 1
    fi
}

check_nic_name() {
    if [ -z $g_conn_if ]; then
        msg_err "please enter the nic name at least"
        show_usage
        return 1
    fi
    echo $g_conn_if | grep -E "^[A-Za-z0-9_\.]+$" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        msg_err "The network adapter parameters are incorrect"
        return 1
    fi
    sudo /usr/sbin/ifconfig $g_conn_if > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        msg_show "there is no nic exits bind to kernel!"
    fi
}

check_numa_pages() {
    numa_num=$(lscpu | grep "NUMA node(s)" | awk '{print $3}')
    # todo : check the maxmum and minimum of the page numbers, make sure the system available mem support
    g_hugepages=${g_hugepages:-1024}
    msg_show "make sure the huge mem is large enough & not extend the maximum of system mem!"
    myPage=(${g_hugepages//\,/ })
    g_hugepages=""
    local i
    for ((i = 0; i < $numa_num; i++)); do
        if [ -z $(echo ${myPage[i]} | grep -E '^[0-9]+$') ]; then
            g_hugepages=${g_hugepages}0,
        else
            g_hugepages=${g_hugepages}${myPage[i]},
        fi
    done
    g_hugepages=${g_hugepages%?}
}

check_switch_param() {
    if [ $1 != 1 ] && [ $1 != 0 ]; then
        msg_err "the switch_param to set is error, please use 1/0 instead!"
        return 1
    else
        return 0
    fi
}

check_args() {
    local ret=0
    check_nic_name
    ret=$(($? + ret))
    check_numa_pages
    ret=$(($? + ret))
    g_daemon_mod=${g_daemon_mod:-1}
    check_switch_param $g_daemon_mod
    ret=$(($? + ret))
    g_kni_switch=${g_kni_switch:-0}
    check_switch_param $g_kni_switch
    ret=$(($? + ret))
    g_low_power=${g_low_power:-0}
    check_switch_param $g_low_power
    ret=$(($? + ret))
    g_useltran=${g_useltran:-0}
    check_switch_param $g_useltran
    g_listen_shadow=${g_listen_shadow:-1}
    check_switch_param $g_listen_shadow
    ret=$(($? + ret))
    g_ltrancore=${g_ltrancore:-0,1}
    g_lstackcore=${g_lstackcore:-2}
    if [ $ret -eq 0 ]; then
        msg_show "the args is reasonable..."
    else
        msg_err "the args is unreasonalble..."
        exit 1
    fi
}

get_current_user_group() {
    cur_user=$USER
    cur_group=$(groups)
}

change_file_permissions() {
    get_current_user_group

    __mkdir /var/run/gazelle
    __chown $PROJ_ROOT/gazelle_setup.sh
    __chown $PROJ_ROOT/gazelle_crontab.sh
    __chown $PROJ_ROOT/gazelle_exit.sh
    __chown $PROJ_ROOT/gazelle_common.sh
    sudo chmod u+x $PROJ_ROOT/gazelle_setup.sh
    sudo chmod u+x $PROJ_ROOT/gazelle_crontab.sh
    sudo chmod u+x $PROJ_ROOT/gazelle_exit.sh
    sudo chmod u+x $PROJ_ROOT/gazelle_common.sh

    __chown /usr/bin/ltran > /dev/null
    __chown /usr/bin/gazellectl > /dev/null
    __chown $CONF_DIR
    __chown /lib64/liblstack.so
    __chown $DPDK_DEVBIND

    sudo setcap 'CAP_DAC_OVERRIDE,CAP_SYS_RAWIO,CAP_SYS_ADMIN+ep' /usr/bin/ltran
    sudo setcap 'CAP_DAC_OVERRIDE+ep' /usr/bin/gazellectl

    msg_show "set ${cur_user}:${cur_group} success"
}

setup_dpdk() {
    install_nic_mod
    if [ $? -ne 0 ]; then
        msg_err "load nic module failed..."
        exit 1
    fi

    load_libos_kni_module
    if [ $? -ne 0 ]; then
        remove_kni_module
        msg_err "load kni module failed..."
        exit 1
    fi

    bind_devices_to_dpdk
    if [ $? -ne 0 ]; then
        nic_recover
        msg_err "bind nic to modules failed, try to recover the nic..."
        exit 1
    fi

    set_numa_pages $g_hugepages
    if [ $? -ne 0 ]; then
        clear_huge_pages
        nic_recover
        msg_err "set numa failed"
        exit 1
    fi
}

gen_ltran_conf() {
    if [ ! -f $CONF_DIR/ltran.conf ]; then
        msg_err "the default ltran conf does not exits"
        return 1
    fi

    sed -i "/^dispatch_subnet[^_]/c dispatch_subnet=\"$g_subnet\"" $CONF_DIR/ltran.conf
    sed -i "/^dispatch_subnet_length/c dispatch_subnet_length=$g_subnet_len" $CONF_DIR/ltran.conf
    sed -i "/^bond_macs/c bond_macs=\"$g_netcard_mac\"" $CONF_DIR/ltran.conf
    sed -i "/^kni_switch/c kni_switch = $g_kni_switch" $CONF_DIR/ltran.conf

    local old_ltrancore=$(grep forward_kit_args $CONF_DIR/ltran.conf | awk -F '-l' '{print $2}' | awk '{print $1}')
    sed -i "/^forward_kit_args/s/-l ${old_ltrancore}/-l ${g_ltrancore}/" $CONF_DIR/ltran.conf

    return 0
}

function parse_cpu_count() {
    cpu_nums=$1
    cpu_count=0
    for cpu_list in $(echo ${cpu_nums} | awk -F, '{for (i=1;i<=NF;i++)printf("%s\n", $i)}'); do
        pre=$(echo $cpu_list | awk -F- '{print $1}')
        next=$(echo $cpu_list | awk -F- '{print $2}')
        if [ -z $next ]; then
            ((cpu_count++))
            continue
        fi
        for ((i = $pre; i <= $next; i++)); do
            ((cpu_count++))
        done
    done
    echo "$cpu_count"
}

gen_lstack_conf() {
    if [ ! -f $CONF_DIR/lstack.conf ]; then
        msg_err "the default lstack conf does not exits"
        return 1
    fi

    sed -i "/^low_power_mode/c low_power_mode = $g_low_power" $CONF_DIR/lstack.conf
    sed -i "/^use_ltran/c use_ltran = $g_useltran" $CONF_DIR/lstack.conf
    sed -i "/^mask_addr/c mask_addr=\"$g_subnet_mask\"" $CONF_DIR/lstack.conf
    sed -i "/^host_addr/c host_addr=\"$g_conn_my_ip\"" $CONF_DIR/lstack.conf
    sed -i "/^gateway_addr/c gateway_addr=\"$g_gateway\"" $CONF_DIR/lstack.conf
    sed -i "/^devices/c devices=\"$g_kni_mac\"" $CONF_DIR/lstack.conf

    if [ ${g_useltran} -eq 0 ]; then
        sed -i "/^kni_switch/c kni_switch = $g_kni_switch" $CONF_DIR/lstack.conf
    else 
        sed -i "/^kni_switch/c kni_switch = 0" $CONF_DIR/lstack.conf
    fi

    shadow_exist=$(grep listen_shadow $CONF_DIR/lstack.conf)
    if [ -n "${shadow_exist}" ];then
        sed -i "/^listen_shadow/c listen_shadow = $g_listen_shadow" $CONF_DIR/lstack.conf
    else
        sed -i "/^use_ltran/a\listen_shadow = $g_listen_shadow" $CONF_DIR/lstack.conf
    fi

    # num_cpus
    local old_lstackcore=$(grep num_cpus $CONF_DIR/lstack.conf | awk -F= '{print $2}' | awk -F "\"" '{print $2}')
    sed -i "/^num_cpus/s/${old_lstackcore}/${g_lstackcore}/" $CONF_DIR/lstack.conf

    local old_numa=$(grep dpdk_args $CONF_DIR/lstack.conf | awk -F "-socket-mem" '{print $2}' | awk '{print $2}' | awk -F "\"" '{print $2}')
    old_numa="\"${old_numa}\","
    sed -i "/^dpdk_args/s/${old_numa}/\"${g_hugepages}\",/" $CONF_DIR/lstack.conf
    local cpu_count=$(parse_cpu_count ${g_lstackcore})
    tcp_conn_count=1500
    mbuf_count_per_conn=$(expr 170 \* ${cpu_count})

    sed -i "/^tcp_conn_count/c tcp_conn_count=${tcp_conn_count}" $CONF_DIR/lstack.conf
    sed -i "/^mbuf_count_per_conn/c mbuf_count_per_conn=${mbuf_count_per_conn}" $CONF_DIR/lstack.conf
}

gen_run_param() {
    msg_show "start recording the key data!"
    if [ ! -d /var/run/gazelle/ ]; then
        sudo mkdir -p /var/run/gazelle/
    fi
    if [ -f $PARAM_PATH ]; then
        sudo rm -f $PARAM_PATH
    fi
    sudo touch $PARAM_PATH
    __chown $PARAM_PATH
    echo "nic=$g_conn_if" >> $PARAM_PATH
    echo "ipAddr=$g_conn_my_ip" >> $PARAM_PATH
    echo "mac=$g_kni_mac" >> $PARAM_PATH
    echo "prefix=$g_prefix" >> $PARAM_PATH
    echo "subnet=$g_subnet" >> $PARAM_PATH
    echo "gateway=$g_gateway" >> $PARAM_PATH
    echo "ltran= --config-file=$CONF_DIR/ltran.conf" >> $PARAM_PATH

    pci_num=$($DPDK_DEVBIND -s | grep $g_conn_if | awk '{print $1}')
    ker_drv=$($DPDK_DEVBIND -s | grep $g_conn_if | awk '{print $7}' | awk '-F[=]' '{print $2}')
    echo "pci_num=$pci_num" >> $PARAM_PATH
    echo "ker_drv=$ker_drv" >> $PARAM_PATH
}

set_crontab() {
    sudo cat /etc/cron.allow | grep ${cur_user} > /dev/null
    if [ $? != 0 ]; then
        msg_show "add gazelle into cron.allow"
        sudo sh -c "echo ${cur_user} >> /etc/cron.allow"
    fi

    crontab -l 2> /dev/null | grep ${crontab_cmd} > /dev/null
    if [ $? == 0 ]; then
        return 0
    fi

    msg_show "add gazelle crontab task"
    crontab -l > /dev/null 2>&1
    if [ $? != 0 ]; then
        echo "* * * * * flock -w 60 -o -x $CRONTAB_LOCK -c \"${crontab_cmd} ${g_daemon_mod}\" " > ./gazelle_crontab_tmp && crontab ./gazelle_crontab_tmp && rm -fr ./gazelle_crontab_tmp
    else
        crontab -l > ./gazelle_crontab_tmp && echo "* * * * * flock -w 60 -o -x $CRONTAB_LOCK -c \"${crontab_cmd} ${g_daemon_mod}\" " >> ./gazelle_crontab_tmp && crontab ./gazelle_crontab_tmp && rm -fr ./gazelle_crontab_tmp
    fi
    # Start the task immediately instead of waiting for a full minute
    flock -w 60 -o -x $CRONTAB_LOCK -c "${crontab_cmd} ${g_daemon_mod}" &> /dev/null &
}

##############################################
#starting the env prepare
ARGS=$(getopt -o i:n:d:k:l:h --long nic:,numa:,useltran:,listenshadow:,daemon:,kni:,lowpower:,lstackcore:,ltrancore:,help -n "$0" -- "$@")
if [ $? != 0 ]; then
    echo "Terminating..."
    exit 1
fi
eval set -- "${ARGS}"

while true; do
    case "$1" in
        -i | --nic)
            g_conn_if=$2
            shift 2
            ;;
        -n | --numa)
            g_hugepages=$2
            shift 2
            ;;
        -d | --daemon)
            g_daemon_mod=$2
            shift 2
            ;;
        -k | --kni)
            g_kni_switch=$2
            shift 2
            ;;
        -l | --lowpower)
            g_low_power=$2
            shift 2
            ;;
        --useltran)
            g_useltran=$2
            shift 2
            ;;
        --listenshadow)
            g_listen_shadow=$2
            shift 2
            ;;
        --ltrancore)
            g_ltrancore=$2
            shift 2
            ;;
        --lstackcore)
            g_lstackcore=$2
            shift 2
            ;;
        -h | --help)
            show_usage
            shift 1
            exit 0
            ;;
        --)
            break
            ;;
        *)
            echo "command format error"
            show_usage
            exit 1
            ;;
    esac
done

check_args $@

##############################################
if [ $uname_M == "aarch64" ]; then
    msg_show "CPU: ARM"
elif [ $uname_M == "x86_64" ]; then
    msg_show "CPU: x86"
else
    msg_err "CPU type $uname_M error"
    exit 1
fi

# check ltran
check_ltran
if [ $? -eq 0 ]; then
    msg_show "ltran started"
    exit 1
fi

##############################################
#check_init $@
change_file_permissions
setup_global_variables $g_conn_if
if [ $? -ne 0 ]; then
    msg_err "set up global variables failed..."
    exit 1
fi

##############################################
# generate the info need to record
# path=$PARAM_PATH
msg_show "generate the run param in $PARAM_PATH"
gen_run_param

##############################################
# dpdk initialize
msg_show "-----------------"
msg_show "start dpdk"
setup_dpdk
__chown /mnt/hugepages-ltran
__chown /mnt/hugepages-lstack

##############################################
# generate the conf file
# path : /etc/gazelle/
msg_show "generate the conf file in the path $CONF_DIR"
if [ ! -d $CONF_DIR ]; then
    nic_recover
    msg_err "the default conf path does not exits"
    exit 1
fi
gen_ltran_conf
if [ $? -ne 0 ]; then
    nic_recover
    msg_err "modify the ltran.conf failed!"
    exit 1
fi
gen_lstack_conf
if [ $? -ne 0 ]; then
    nic_recover
    msg_err "modify the lstack.conf failed!"
    exit 1
fi

##############################################
# unmanage kni
unmanage_kni() {
    sudo sh -c "echo '[main]' > /etc/NetworkManager/conf.d/gazelle.conf"
    sudo sh -c "echo 'plugins=keyfile' >> /etc/NetworkManager/conf.d/gazelle.conf"
    sudo sh -c "echo '[keyfile]' >> /etc/NetworkManager/conf.d/gazelle.conf"
    sudo sh -c "echo 'unmanaged-devices=interface-name:kni' >> /etc/NetworkManager/conf.d/gazelle.conf"

    sudo systemctl status NetworkManager | grep -w active > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        sudo systemctl reload NetworkManager
        sleep 1
    fi
}
if [ $g_kni_switch = 1 ]; then
    unmanage_kni
fi

##############################################
# start ltran
if [ $g_useltran -eq 0 ];then
    msg_show "gen lstack conf success"
    exit 0
fi
msg_show "start ltran on $g_conn_if"
msg_show "start ltran by $cur_user"
XDG_RUNTIME_DIR=/tmp nohup /usr/bin/ltran --config-file=$CONF_DIR/ltran.conf > /dev/null 2>&1 &

check_ltran 120
if [ $? -ne 0 ]; then
    msg_err "ltran start failed! Please check ltran's log for the reason of the problem."
    nic_recover
    exit 1
else
    msg_show "successfully started ltran"
    if [ $g_kni_switch = 1 ]; then
        configure_nic "usr"
    fi
    if [ $? -ne 0 ]; then
        msg_err "config kni failed!"
        nic_recover
        exit 1
    else
        msg_show "config kni success"
    fi
fi

##############################################
# start the daemon task, use crontab
msg_show "starting the ltran crontab!"
set_crontab

##############################################
msg_show "successfully started the ltran..."
