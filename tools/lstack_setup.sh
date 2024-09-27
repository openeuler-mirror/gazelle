#!/bin/bash
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
# Description: Prepare the environment for gazelle and start the ltran process!

PROJ_ROOT=$(
    cd $(dirname $0)/
    pwd
)

confPath="/etc/gazelle/lstack.conf"
backupPath="/etc/gazelle/lstack.conf.bak"
selectConf="$confPath"

declare -A lstack_settings
lstack_settings=(
    ["use_ltran"]="是否使用ltran？:number:0,1"
    ["listen_shadow"]="是否使用影子fd监听，单个listen线程多个协议栈线程时使用:number:0,1"
    ["num_cpus"]="lstack线程绑定的cpu编号，编号的数量为lstack线程个数(小于等于网卡多队列数量)。可按NUMA选择cpu:string"
    ["app_bind_numa"]="应用的epoll和poll线程是否绑定到协议栈所在的numa，缺省值是1，即绑定:number:0,1"
    ["app_exclude_cpus"]="应用的epoll和poll线程不会绑定到的cpu编号，app_bind_numa = 1时才生效。示例：\"7,8,9 ...\":string"
    ["low_power_mode"]="是否开启低功耗模式，暂不支持:number:0,1"
    ["kni_switch"]="rte_kni开关，默认为0。只有不使用ltran时才能开启:number:0,1"
    ["unix_prefix"]="gazelle进程间通信使用的unix socket文件前缀字符串，默认为空，和需要通信的ltran.conf的unix_prefix或gazellectl的-u参数配置一致。不能含有特殊字符，最大长度为128:string"
    ["host_addr"]="协议栈的IP地址，必须和redis-server配置文件里的“bind”字段保存一致:string"
    ["mask_addr"]="掩码地址:string"
    ["gateway_addr"]="网关地址:string"
    ["devices"]="网卡通信的mac地址，需要与ltran.conf的bond_macs配置一致；在lstack bond1模式下，可指定bond1的主接口，取值为bond_slave_mac之一:string"
    ["send_connect_number"]="设置为正整数，表示每次协议栈循环中发包处理的连接个数:number"
    ["read_connect_number"]="设置为正整数，表示每次协议栈循环中收包处理的连接个数:number"
    ["rpc_number"]="设置为正整数，表示每次协议栈循环中rpc消息处理的个数:number"
    ["nic_read_num"]="设置为正整数，表示每次协议栈循环中从网卡读取的数据包的个数:number"
    ["tcp_conn_count"]="tcp的最大连接数，该参数乘以mbuf_count_per_conn是初始化时申请的mbuf池大小，配置过小会启动失败，tcp_conn_count * mbuf_count_per_conn * 2048字节不能大于大页大小:number"
    ["mbuf_count_per_conn"]="每个tcp连接需要的mbuf个数，该参数乘以tcp_conn_count是初始化时申请的mbuf地址池大小，配置过小会启动失败，tcp_conn_count * mbuf_count_per_conn * 2048字节不能大于大页大小:number"
    ["nic_rxqueue_size"]="网卡接收队列深度，范围512-8192，缺省值是4096:number"
    ["nic_txqueue_size"]="网卡发送队列深度，范围512-8192，缺省值是2048:number"
    ["nic_vlan_mode"]="vlan模式开关，变量值为vlanid，取值范围-1~4094，-1关闭，缺省值是-1:number"
    ["bond_mode"]="bond模式，目前支持ACTIVE_BACKUP/8023AD/ALB三种模式，对应的取值是1/4/6；当取值为-1或者NULL时，表示未配置bond:number:1,4,6,-1"
    ["bond_slave_mac"]="用于组bond的两个子口的mac地址:string"
    ["bond_miimon"]="链路监控时间，单位为ms，取值范围为1到2^31 - 1，缺省值为10ms:number"
    ["flow_bifurcation"]="流量分叉开关(替代kni方案)，通过gazelle将不支持处理的报文转发到内核，缺省值是0，即关闭:number:0,1"
    ["stack_thread_mode"]="默认即可:string"
)

keys=(
    "use_ltran"
    "listen_shadow"
    "num_cpus"
    "app_bind_numa"
    "app_exclude_cpus"
    "low_power_mode"
    "kni_switch"
    "unix_prefix"
    "host_addr"
    "mask_addr"
    "gateway_addr"
    "devices"
    "send_connect_number"
    "read_connect_number"
    "rpc_number"
    "nic_read_num"
    "tcp_conn_count"
    "mbuf_count_per_conn"
    "nic_rxqueue_size"
    "nic_txqueue_size"
    "nic_vlan_mode"
    "bond_mode"
    "bond_slave_mac"
    "bond_miimon"
    "flow_bifurcation"
    "stack_thread_mode"
)

declare -A conditions
conditions=(
    ["app_exclude_cpus"]="app_bind_numa=1"
    ["kni_switch"]="ltran=0"
)

dpdk_para_args=("--socket-mem" "--huge-dir" "--proc-type" "--iova-mode")
dpdk_onoff_args=("--legacy-mem" "--map-perfect" "-d")

ask_for_start() {
    while true; do
        read -p "是否继续进行lstack进行配置？(y/n): " ifstart
        case "$ifstart" in
            [yY][eE][sS]|[yY]|"")
                ifstart=true
                break
                ;;
            [nN][oO]|[nN])
                ifstart=false
                break
                ;;
            *)
                echo "输入有误，请重新输入！"
                ;;
        esac
    done
    
    if [ "$ifstart" == false ]; then
        echo "已退出lstack配置"
        exit 0
    fi
}

check_backup_config() {
    if [ -f "$backupPath" ]; then
        while true; do
            read -p "是否从已有的配置文件开始？输入 'y' 使用已有配置，输入 'n' 使用默认配置 (y/n): " userChoice
            case "$userChoice" in
                [yY][eE][sS]|[yY]|"")
                    selectConf="$confPath"
                    break
                    ;;
                [nN][oO]|[nN])
                    selectConf="$backupPath"
                    break
                    ;;
                *)
                    echo "输入有误，请重新输入！"
                    ;;
            esac
        done
    else
        cp "$confPath" "$backupPath"
    fi
}

read_config() {
    origin_setting_text=$(<"$selectConf")
    # 读取配置文件并处理
    while IFS= read -r line; do
        text=$(echo "$line" | tr -d ' ') # 去除空格
        if [ -z "$text" ] || [[ $text == \#* ]]; then
            continue
        fi
    
        IFS='=' read -r name value <<< "$text"
    
        if [ "$name" == "dpdk_args" ]; then
            dpdk_data=($(echo $value | sed 's/[][]//g' | tr -d '"' | tr ',' '\n' | xargs))
        fi
    
        if [ -n "${lstack_settings[$name]}" ]; then
            IFS=':' read -r tip type choice <<< "${lstack_settings[$name]}"
            
            if [ "$type" == "number" ]; then
                lstack_settings["$name,default"]=$(echo "$value")
            elif [ "$type" == "string" ]; then
                lstack_settings["$name,default"]=$(echo "$value")
            fi
        fi
    done <<< "$origin_setting_text"
}

set_dpdk_args() {
    output_args=()
    # 处理参数设置
    for name in "${dpdk_para_args[@]}"; do
        if [[ " ${dpdk_data[@]} " =~ " ${name} " ]]; then
            index=$(printf "%s\n" "${dpdk_data[@]}" | grep -n -w -- "$name" | cut -d: -f1)
            default_value="${dpdk_data[index]}"
            read -p "请设定dpdk参数${name}值，默认值为${default_value}：" userChoice
            userChoice=${userChoice:-$default_value}
            output_args+=("$name" "$userChoice")
        else
            read -p "请设定dpdk参数${name}值，默认跳过不使用该参数：" userChoice
            if [ -n "$userChoice" ]; then
                output_args+=("$name" "$userChoice")
            fi
        fi
    done
    
    # 处理开关参数
    for name in "${dpdk_onoff_args[@]}"; do
        default_value=false
        if [[ " ${dpdk_data[@]} " =~ " ${name} " ]]; then
            default_value=true
        fi
        while true; do
            read -p "是否使用dpdk参数${name}，默认为$(if $default_value; then echo "启用"; else echo "不启用"; fi) (y/n)：" userChoice
            userChoice=${userChoice,,}  # 转换为小写
            if [ -z "$userChoice" ]; then
                userChoice=$default_value
                break
            elif [[ "$userChoice" =~ ^(y|yes)$ ]]; then
                userChoice=true
                break
            elif [[ "$userChoice" =~ ^(n|no)$ ]]; then
                userChoice=false
                break
            else
                echo "输入有误，请重新输入！"
            fi
        done
        if $userChoice; then
            output_args+=("$name")
        fi
    done
    
    outputtext="${output_args[*]}"
}

set_lstack_args() {
    # echo $outputtext
    for name in "${keys[@]}"; do
        IFS=":" read -r tip type choice <<< "${lstack_settings[$name]}"
        default="${lstack_settings[$name,default]}"
    
        # 检查条件
        if [[ -n "${conditions[$name]}" && "$outputtext" != *"${conditions[$name]}"* ]]; then
            continue
        fi
    
        options_text=""
        if [[ -n "$choice" ]]; then
            options_text="可选项：$choice，"
        fi
    
        if [[ -n "$default" ]]; then
            text="请输入${name}参数。说明：${tip}。${options_text}默认为${default}："
        else
            text="请输入${name}参数。说明：${tip}。默认为不设置${options_text}："
        fi
    
        while true; do
            read -p "$text" userChoice
    
            if [[ -z "$userChoice" ]]; then
                if [[ -n "$default" ]]; then
                    validChoice="$default"
                    break
                else
                    validChoice=""
                    break
                fi
            fi
    
            if [[ "$type" == "number" ]]; then
                if [[ -n "$choice" ]]; then
                    if [[ ",$choice," == *",$userChoice,"* ]]; then
                        validChoice="$userChoice"
                        break
                    fi
                else
                    if [[ "$userChoice" =~ ^[0-9]+$ ]]; then
                        validChoice="$userChoice"
                        break
                    fi
                fi
            elif [[ "$type" == "string" ]]; then
                userChoice="${userChoice//\"/}"
                if [[ -z "$choice" || ",$choice," == *",$userChoice,"* ]]; then
                    validChoice="\"$userChoice\""
                    break
                fi
            fi
            echo "输入参数格式有误，请重新输入!"
        done
    
        if [[ -n "$validChoice" ]]; then
            outputtext+="${name}=${validChoice}\n"
        fi
    done
}

save_config() {
    echo "以下是最终得到的配置内容："
    echo -e "$outputtext"
    while true; do
        read -p "您确定要保存这些内容吗？默认配置文件已备份于$backupPath (y/n): " confirm
        case "$confirm" in
            [yY][eE][sS]|[yY]|"")
                # 保存到指定位置
                echo "$outputtext" > $confPath
                echo "内容已保存到 $confPath"
                break
                ;;
            [nN][oO]|[nN])
                echo "未进行保存，配置已结束。"
                break
                ;;
            *)
                echo "输入有误，请输入 y 或 n。"
                ;;
        esac
    done
}

ask_for_start
check_backup_config
read_config
set_dpdk_args
set_lstack_args
save_config
