#!/bin/bash
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
# Description: the common functions of gazelle_env_prepare script

PROJ_ROOT=$(
    cd $(dirname $0)/
    pwd
)
DPDK_KMOD_DIR=$(dirname $(rpm -ql dpdk | grep igb_uio.ko))
DPDK_DEVBIND=$(rpm -ql dpdk | grep dpdk-devbind.py)
PARAM_PATH="/var/run/gazelle/run_param"
CRONTAB_LOCK=$(dirname $PARAM_PATH)/crond.lock
CONF_DIR=/etc/gazelle

# ip and nic for communication
g_conn_my_ip=""
g_conn_if=""
g_conn_if_kni="kni"

# subnet configure
g_subnet=""
g_subnet_mask=""
g_prefix=""
g_subnet_len=""
g_gateway=""
g_premask=""

# global variables initialized when run
g_netcard_mac=""
g_kni_mac=""
g_default_route="$(sudo ip route | grep default)"

# port of dpdk
g_dpdk_port=""

msg_show() {
    echo -e "$(date '+[%Y-%m-%d %H:%M:%S]') [INFO] $*"
}

msg_err() {
    echo -e "\033[1;31m$(date '+[%Y-%m-%d %H:%M:%S]') [ERROR] $*\033[0m"
}

check_dependence() {
    if [ $(sudo rpm -qa | grep -w $1 | wc -l) -ne 0 ]; then
        msg_show "check $1 succeeded!"
        return 0
    else
        msg_err "check $1 failed, try to install $1"
        sudo yum install $1 -y
        if [ $? -ne 0 ]; then
            msg_err "install $1 failed, please try it yourself..."
            return 1
        else
            msg_show "try to install $1 succeeded."
            return 0
        fi
    fi
}

setup_global_variables() {
    msg_show "setting up the key value for prepare..."
    g_conn_if=$1
    g_conn_my_ip=$(/usr/sbin/ifconfig $g_conn_if | grep -w "inet" | awk '{print $2}')
    if [ -z ${g_conn_my_ip} ]; then
        msg_err "The specified network adapter does not have an IP address!"
        return 1
    fi
    g_subnet_mask=$(/usr/sbin/ifconfig $g_conn_if | grep -w "inet" | awk '{print $4}')
    g_netcard_mac=$(/usr/sbin/ifconfig $g_conn_if | grep -w "ether" | awk '{print $2}')
    local route_info=$(/usr/sbin/ip route | grep $g_conn_if | grep default)
    if [ -z "$route_info" ]; then
        g_gateway=$(/usr/sbin/ip route | grep -w "$g_conn_if" | head -n 1 | awk '{print $1}' | awk '-F[/]' '{print $1}')
        g_prefix=$(/usr/sbin/ip route | grep -w "$g_conn_if" | head -n 1 | awk '{print $1}' | awk '-F[/]' '{print $2}')
    else
        g_gateway=$(echo $route_info | awk '{print $3}')
        g_prefix=$(/usr/sbin/ip route | grep -w $g_conn_if | grep -v default | head -n 1 | awk '{print $1}' | awk '-F[/]' '{print $2}')
    fi
    if [ -z $g_prefix ]; then
        msg_err "The route information is incomplete. Please check."
        return 1
    fi
    # calculate the subnet configure
    myip=(${g_conn_my_ip//\./ })
    mymask=(${g_subnet_mask//\./ })
    local i
    for ((i = 0; i < 4; i++)); do
        g_subnet=${g_subnet}$((${mymask[i]} & ${myip[i]})).
        g_premask=${g_premask}$(($((mymask[i] ^ 255)) | ${myip[i]})).
    done
    g_subnet=${g_subnet%?}
    g_premask=${g_premask%?}
    g_subnet_len=$((32 - $g_prefix))
    g_kni_mac=$g_netcard_mac
    return 0
}

remove_igb_uio_module() {
    msg_show "Unloading any existing DPDK UIO module"
    /sbin/lsmod | grep -s igb_uio > /dev/null
    if [ $? -eq 0 ]; then
        sudo /sbin/rmmod igb_uio
    fi
    /sbin/lsmod | grep -s uio > /dev/null
    if [ $? -eq 0 ]; then
        sudo /sbin/rmmod uio
    fi
}

load_igb_uio_module() {
    /sbin/lsmod | grep -w uio > /dev/null
    if [ $? -ne 0 ]; then
        sudo modinfo uio > /dev/null
        if [ $? -eq 0 ]; then
            msg_show "Loading uio module"
            sudo /sbin/modprobe uio
        fi
    fi

    # UIO may be compiled into kernel, so it may not be an error if it can't be loaded.
    if [ ! -f $DPDK_KMOD_DIR/igb_uio.ko ]; then
        msg_err "## ERROR: Target does not have the DPDK UIO Kernel Module."
        msg_err "       To fix, please try to rebuild target."
        return 1
    fi

    /sbin/lsmod | grep -w igb_uio > /dev/null
    if [ $? -ne 0 ]; then
        if [ -f $DPDK_KMOD_DIR/igb_uio.ko ]; then
            msg_show "Loading igb_uio module"
            sudo /sbin/insmod $DPDK_KMOD_DIR/igb_uio.ko
            if [ $? -ne 0 ]; then
                msg_err "## ERROR: Could not load igb_uio.ko."
                return 1
            fi
        else
            msg_err "$DPDK_KMOD_DIR/igb_uio.ko does not exist"
            return 1
        fi
    fi
}

load_vfio_module() {
    /sbin/lsmod | grep -w vfio-pci > /dev/null
    if [ $? -ne 0 ]; then
        sudo modinfo vfio > /dev/null
        if [ $? -eq 0 ]; then
            msg_show "Loading vfio module"
            sudo /sbin/modprobe vfio enable_unsafe_noiommu_mode=1
        else
            msg_err "the vfio module is not exist"
            return 1
        fi
        sudo modinfo vfio-pci > /dev/null
        if [ $? -eq 0 ]; then
            msg_show "Loading vfio-pci module"
            sudo /sbin/modprobe vfio-pci
        else
            msg_err "the vfio-pci module is not exist"
            return 1
        fi
    fi
}

remove_vfio_module() {
    msg_show "Unloading any existing DPDK vfio module"
    /sbin/lsmod | grep -sw vfio_pci > /dev/null
    if [ $? -eq 0 ]; then
        sudo /sbin/rmmod vfio_pci
    fi
}

remove_kni_module() {
    msg_show "Unloading any existing DPDK KNI module"
    /sbin/lsmod | grep -sw rte_kni > /dev/null
    if [ $? -eq 0 ]; then
        sudo /sbin/rmmod rte_kni
    fi
}

load_libos_kni_module() {
    # Check that the KNI module is already built.
    if [ ! -f $DPDK_KMOD_DIR/rte_kni.ko ]; then
        msg_err "## ERROR: Target does not have the DPDK KNI Module."
        msg_err "       To fix, please try to rebuild target."
        return 1
    fi

    # Now try load the KNI module.
    /sbin/lsmod | grep -sw rte_kni > /dev/null
    if [ $? -ne 0 ]; then
        if [ -f $DPDK_KMOD_DIR/igb_uio.ko ]; then
            msg_show "Loading rte_kni module"
            sudo /sbin/insmod $DPDK_KMOD_DIR/rte_kni.ko kthread_mode="single" carrier="on"
            if [ $? -ne 0 ]; then
                msg_err "## ERROR: Could not load rte_kni.ko."
                return 1
            fi
        else
            msg_err "$DPDK_KMOD_DIR/rte_kni.ko does not exist"
        fi
    fi
}

check_nic_type() {
    local nic_type=$($DPDK_DEVBIND --status-dev net | grep $1 | awk '{print $7}' | awk '-F[=]' '{print $2}')
    if [ "$nic_type" = "virtio-pci" ]; then
        return 0
    else
        return 1
    fi
}

install_nic_mod() {
    check_nic_type $g_conn_if
    if [ $? -eq 0 ]; then
        msg_show "Selected nic is virtual net card"
        load_igb_uio_module
        if [ $? -ne 0 ]; then
            remove_igb_uio_module
            return 1
        fi
    else
        msg_show "Selected nic is physical net card"
        load_vfio_module
        if [ $? -ne 0 ]; then
            remove_vfio_module
            return 1
        fi
    fi
}

create_mnt_huge() {
    msg_show "Creating /mnt/hugepages-ltran and mounting as hugetlbfs"
    sudo mkdir -p /mnt/hugepages-ltran
    sudo mkdir -p /mnt/hugepages-lstack

    grep -s "/mnt/hugepages-ltran " /proc/mounts > /dev/null
    if [ $? -ne 0 ]; then
        sudo mount -t hugetlbfs nodev /mnt/hugepages-ltran
    fi

    grep -s "/mnt/hugepages-lstack " /proc/mounts > /dev/null
    if [ $? -ne 0 ]; then
        sudo mount -t hugetlbfs nodev /mnt/hugepages-lstack
    fi
}

set_numa_pages() {
    HUGEPGSZ=$(cat /proc/meminfo | grep Hugepagesize | cut -d : -f 2 | awk '{printf $1}')
    HUGEPGSZ_NAME=$(cat /proc/meminfo | grep Hugepagesize | cut -d : -f 2 | tr -d ' ')
    HUGEPGS_NUM_NUMA=(${g_hugepages//\,/ })
    local ltran_numa
    # Unit is kB
    ltran_numa=$(( (1024 * 1024 + ${HUGEPGSZ} - 1) / ${HUGEPGSZ}))
    msg_show "Reserving hugepages"
    msg_show "If the shell is stuck, check whether the huge page is correct."

    numa_num=$(lscpu | grep "NUMA node(s)" | awk '{print $3}')
    local i
    for ((i = 0; i < $numa_num; i++)); do
        # Unit is kB
        HUGEPGS_NUM_NUMA[i]=$(( (${HUGEPGS_NUM_NUMA[i]} * 1024  + ${HUGEPGSZ} - 1) / ${HUGEPGSZ}))
        if [ $i -eq 0 ]; then
            HUGEPGS_NUM_NUMA[i]=$((${HUGEPGS_NUM_NUMA[i]} + ${ltran_numa}))
        fi
        echo > .echo_tmp
        msg_show "${HUGEPGS_NUM_NUMA[i]} of pages for node$i: "
        echo "echo ${HUGEPGS_NUM_NUMA[i]} > /sys/devices/system/node/node${i}/hugepages/hugepages-${HUGEPGSZ_NAME}/nr_hugepages" >> .echo_tmp
        sudo sh .echo_tmp
        if [ $? -ne 0 ]; then
            msg_err "sudo echo ${HUGEPGS_NUM_NUMA[i]} > /sys/devices/system/node/node${i}/hugepages/hugepages-${HUGEPGSZ_NAME}/nr_hugepages failed!"
            return 1
        fi
        rm -f .echo_tmp
        pages=$(cat /sys/devices/system/node/node${i}/hugepages/hugepages-${HUGEPGSZ_NAME}/nr_hugepages)
        if [ $pages -ne ${HUGEPGS_NUM_NUMA[i]} ]; then
            msg_err "sudo echo ${HUGEPGS_NUM_NUMA[i]} > /sys/devices/system/node/node${i}/hugepages/hugepages-${HUGEPGSZ_NAME}/nr_hugepages failed!"
            return 1
        fi
    done

    create_mnt_huge
}

# Removes all reserved hugepages.
clear_huge_pages() {
    msg_show "Unmounting /mnt/hugepages-ltran and removing directory"
    grep -s "/mnt/hugepages-ltran " /proc/mounts > /dev/null
    if [ $? -eq 0 ]; then
        sudo umount /mnt/hugepages-ltran
        if [ $? -ne 0 ]; then
            msg_err "sudo umount /mnt/hugepages-ltran failed!"
            return 1
        fi
    fi

    grep -s "/mnt/hugepages-lstack " /proc/mounts > /dev/null
    if [ $? -eq 0 ]; then
        sudo umount /mnt/hugepages-lstack
        if [ $? -ne 0 ]; then
            msg_err "sudo umount /mnt/hugepages-lstack failed!"
            return 1
        fi
    fi
    HUGEPGSZ_NAME=$(cat /proc/meminfo | grep Hugepagesize | cut -d : -f 2 | tr -d ' ')
    echo > .echo_tmp
    for d in /sys/devices/system/node/node?; do
        echo "echo 0 > $d/hugepages/hugepages-${HUGEPGSZ_NAME}/nr_hugepages" >> .echo_tmp
    done
    msg_show "Removing currently reserved hugepages"
    sudo sh .echo_tmp
    rm -f .echo_tmp

    if [ -d /mnt/hugepages-ltran ]; then
        sudo rm -R /mnt/hugepages-ltran
        if [ $? -ne 0 ]; then
            msg_err "sudo rm -R /mnt/hugepages-ltran failed!"
            return 1
        fi
    fi
    if [ -d /mnt/hugepages-lstack ]; then
        sudo rm -R /mnt/hugepages-lstack
        if [ $? -ne 0 ]; then
            msg_err "sudo rm -R /mnt/hugepages-lstack failed!"
            return 1
        fi
    fi
    return 0
}

# Uses $DPDK_DEVBIND to move devices to work with dpdk
bind_devices_to_dpdk() {
    dev=$($DPDK_DEVBIND --status-dev net | grep "$g_conn_if" | awk '{print $1}')
    #sudo nmcli connection down $g_conn_if > /dev/null 2>&1
    sudo /usr/sbin/ifconfig $g_conn_if down > /dev/null 2>&1
    local mod_type
    local mod_dir
    check_nic_type $g_conn_if
    if [ $? -eq 0 ]; then
        mod_type="igb_uio"
        mod_dir="igb_uio"
    else
        mod_type="vfio-pci"
        mod_dir="vfio_pci"
    fi
    if [ -d /sys/module/$mod_dir ]; then
        sudo $DPDK_DEVBIND -b $mod_type $dev && msg_show "bind_devices_to_dpdk OK"
    else
        msg_err "# Please load the $mod_type kernel module before querying or "
        msg_err "# adjusting device bindings"
        return 1
    fi
}

bind_nic_to_kernel() {
    msg_show "Bind nic to kernel"
    drv=$(sudo grep ker_drv $PARAM_PATH | awk '-F[=]' '{print $2}')
    pci_id=$(sudo grep pci_num $PARAM_PATH | awk '-F[=]' '{print $2}')
    sudo $DPDK_DEVBIND -b $drv $pci_id || msg_err "$DPDK_DEVBIND -b $drv $pci_id fail"
    nic_num=$(sudo $DPDK_DEVBIND -s | grep "if=" | grep $pci_id | wc -l)
    if [ $nic_num -ne 1 ]; then
        msg_err "$pci_id drv=$drv not bind to virtio_pci as expect"
        sudo $DPDK_DEVBIND -s
        return 1
    fi
}

rm_kni_igb_uio() {
    msg_show "remove igb_uio.ko & rte_kni.ko"
    sudo ifconfig $g_conn_if_kni down

    /sbin/lsmod | grep -w rte_kni && sudo /sbin/rmmod rte_kni
    /sbin/lsmod | grep -w rte_kni
    if [ $? -eq 0 ]; then
        msg_err "rmmod rte_kni failed!"
        return 1
    fi

    /sbin/lsmod | grep -w igb_uio && sudo /sbin/rmmod igb_uio
    /sbin/lsmod | grep -w igb_uio
    if [ $? -eq 0 ]; then
        msg_err "rmmod igb_uio failed!"
        return 1
    fi
}

configure_nic() {
    local default_route=
    if [ ! -f $PARAM_PATH ]; then
        msg_err "no target param file found to config net_card"
        return 1
    fi

    if [ $1 = "usr" ]; then
        msg_show "use virtual kni card"
        net_card=$g_conn_if_kni
        default_route="$(echo $g_default_route | grep $g_conn_if)"
    fi
    if [ $1 = "ker" ]; then
        msg_show "use normal kernel card"
        net_card=$(sudo grep -w nic $PARAM_PATH | awk '-F[=]' '{print $2}')
        default_route="$(echo $g_default_route | grep $g_conn_if_kni)"
    fi

    local i
    for ((i = 0; i < 5; i++)); do
        sudo /usr/sbin/ifconfig $net_card up
        if [ -n "$(sudo ip addr | grep -w $net_card | grep -w "UP")" ]; then
            break;
        fi
        sleep 1
    done
    if [ $i -ge 5 ]; then
        msg_err "The nic does not up, please check the args"
        return 1
    fi

    local local_ipAddr=$(sudo grep ipAddr $PARAM_PATH | awk '-F[=]' '{print $2}')
    local local_mac=$(sudo grep mac $PARAM_PATH | awk '-F[=]' '{print $2}')
    local local_prefix=$(sudo grep prefix $PARAM_PATH | awk '-F[=]' '{print $2}')
    local local_subnet=$(sudo grep subnet $PARAM_PATH | awk '-F[=]' '{print $2}')
    local local_gateway=$(sudo grep gateway $PARAM_PATH | awk '-F[=]' '{print $2}')

    sudo ifconfig $net_card hw ether ${local_mac}
    if [ $? -ne 0 ]; then
        msg_err "config mac failed"
        return 1
    fi
    # todo : check if "metric 10" is needed
    # ip addr add probability of failure
    for ((i = 0; i < 3; i++)); do
        sudo ip addr add ${local_ipAddr}/${local_prefix} dev $net_card
        if [ -n "$(sudo ip addr | grep -w $net_card | grep -w $local_ipAddr)" ]; then
            break
        fi
        sleep 1
    done
    if [ $i -ge 3 ]; then
        msg_err "config ip failed"
        return 1
    fi

    # Use columns as arguments, need to check
    if [ -n "$default_route" ]; then
        tmpvia=$(echo $default_route | awk '{print $3}')
        tmpdev=$(echo $default_route | awk '{print $5}')
        default_route=${default_route/${tmpvia}/${local_gateway}}
        default_route=${default_route/${tmpdev}/${net_card}}

        for ((i = 0; i < 3; i++)); do
            sudo ip route add $default_route
            if [ -n "$(sudo ip route | grep "default" | grep -w $net_card | grep -w $local_gateway)" ]; then
                break
            fi
            sleep 1
        done
        if [ $i -ge 3 ];then
            msg_err "config gateway failed"
            return 1
        fi
    fi

    msg_show "Configure the nic successfully!"
}

nic_recover() {
    msg_show "Trying to recover a possible network card!"
    bind_nic_to_kernel
    if [ $? -ne 0 ]; then
        msg_err "recover the nic failed!"
    else
        configure_nic "ker"
        if [ $? -eq 0 ]; then
            msg_show "Successfully configured the selected nic"
        else
            msg_err "Configure nic failed"
            return 1
        fi
    fi
}

kill_ltran() {
    msg_show "quit ltran"
    gazellectl ltran quit
    sleep 3
    local ltran_pid=$(ps -ef | grep ltran | grep -v grep | awk '{print $2}')
    if [ -n "$ltran_pid" ]; then
        echo "$ltran_pid"
        msg_show "kill ltran"
        sudo kill -9 $(pidof ltran)
    fi
}

check_ltran() {
    times=${1-1}
    local i
    for i in $(seq $times); do
        gazellectl ltran show > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}
