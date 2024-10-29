#!/bin/bash
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
# Description: the common functions of gazelle_env_prepare script

PROJ_ROOT=$(
    cd $(dirname $0)/
    pwd
)

CONFIG_FILE="config.json"

conf_nic=$(grep '"nic"' "$CONFIG_FILE" | sed 's/.*: "\(.*\)",/\1/')
conf_numa=$(grep '"numa"' "$CONFIG_FILE" | sed 's/.*: "\(.*\)",/\1/')
conf_daemon=$(grep '"daemon"' "$CONFIG_FILE" | sed 's/.*: "\(.*\)",/\1/')
conf_kni=$(grep '"kni"' "$CONFIG_FILE" | sed 's/.*: "\(.*\)",/\1/')
conf_lowpower=$(grep '"lowpower"' "$CONFIG_FILE" | sed 's/.*: "\(.*\)",/\1/')
conf_ltrancore=$(grep '"ltrancore"' "$CONFIG_FILE" | sed 's/.*: "\(.*\)",/\1/')
conf_lstackcore=$(grep '"lstackcore"' "$CONFIG_FILE" | sed 's/.*: "\(.*\)"/\1/')

print_help() {
    echo "Gazelle install args:"
    echo "    {-i=<nic name>|--nic=<nic name>}"
    echo "    [-n=<numa mem>]"
    echo "    [-d=<daemon mode>]"
    echo "    [-k=<kni switch>]"
    echo "    [-l=<low power mode>]"
    echo "    [--ltrancore=<ltran core>]"
    echo "    [--lstackcore=<lstack core>]"
    echo "    [--useltran=<use ltran>]"
    echo "    [--listenshadow=<listen shadow>]"
    echo "examples:"
    echo "    gazelle_setup.sh -i eth0 -n 1024,1024 -d 1/0 -k 1/0 -l 1/0 --ltrancore 0,1 --lstackcore 2-3 --useltran 0/1 --listenshadow 0/1"
    echo
}

check_interface_status() {
    output=$(dpdk-devbind -s)
    
    while read -r line; do
        if [[ $line == *"unused="* && $line != *"unused= *Active*"* ]]; then
            nic_name=$(echo "$line" | awk '{print $1}')
    	echo "Gazelle已接管网卡:$nic_name"
            all_active=false
        fi
    done < <(echo "$output")
    
    if $all_active; then
        echo "Gazelle状态：未安装"
    fi
    echo
}

set_interface() {
    interfaces=($(ls /sys/class/net))
    num_interfaces=${#interfaces[@]}
    
    # 提示用户选择网卡
    echo "检测到以下网络接口："
    for i in "${!interfaces[@]}"; do
        echo "$i) ${interfaces[$i]}"
    done
    
    # 处理用户输入
    while true; do
        if [ "$num_interfaces" -eq 1 ]; then
            echo "注意：只有一个网卡，可能会导致终端失效。"
        fi
        echo
        read -p "请输入网卡编号或名称 (默认: 0): " nic_input
    
        if [ -z "$nic_input" ]; then
            # 默认选择第一张网卡
            conf_nic=${interfaces[0]}
            break
        elif [[ "$nic_input" =~ ^[0-9]+$ ]]; then
            # 用户输入数字
            if [ "$nic_input" -ge 0 ] && [ "$nic_input" -lt "$num_interfaces" ]; then
                conf_nic=${interfaces[$nic_input]}
                break
            else
                echo "无效的编号，请重新输入。"
            fi
        else
            # 用户输入网卡名称
            if [[ " ${interfaces[@]} " =~ " $nic_input " ]]; then
                conf_nic=$nic_input
                break
            else
                echo "无效的网卡名称，请重新输入。"
            fi
        fi
    done
    
    echo "选择的网卡是: $conf_nic"
    echo
}

set_numa_pages() {
    HUGEPGSZ=$(cat /proc/meminfo | grep Hugepagesize | cut -d : -f 2 | awk '{printf $1}')
    HUGEPGSZ_NAME=$(cat /proc/meminfo | grep Hugepagesize | cut -d : -f 2 | tr -d ' ')
    HUGEPGS_NUM_NUMA=(${g_hugepages//\,/ })
    local ltran_numa
    ltran_numa=$(((1024 * 1024 + HUGEPGSZ - 1) / HUGEPGSZ))
    numa_num=$(lscpu | grep "NUMA node(s)" | awk '{print $3}')
    local i
    total_hugepages_mem_size=0

    for ((i = 0; i < numa_num; i++)); do
        # 计算每个节点的大页内存大小
        HUGEPGS_NUM_NUMA[i]=$(( (HUGEPGS_NUM_NUMA[i] * 1024 + HUGEPGSZ - 1) / HUGEPGSZ))
        if [ $i -eq 0 ]; then
            HUGEPGS_NUM_NUMA[i]=$((HUGEPGS_NUM_NUMA[i] + ltran_numa))
        fi

        # 计算总的大页内存需求
        total_hugepages_mem_size=$((total_hugepages_mem_size + HUGEPGS_NUM_NUMA[i] * HUGEPGSZ))
    done

    # 获取系统总内存大小
    mem_total_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')

    # 判断是否超过内存限制
    if [ $total_hugepages_mem_size -gt $mem_total_kb ]; then
        #echo "错误：大页内存需求总和超过了系统总内存。所需内存大小：$total_hugepages_mem_size kB，系统内存大小：$mem_total_kb kB."
        echo "错误：大页内存需求总和超过了系统总内存。所需内存大小：$(awk "BEGIN {printf \"%.2f\", $total_hugepages_mem_size/1048576}") GB，系统内存大小：$(awk "BEGIN {printf \"%.2f\", $mem_total_kb/1048576}") GB。请降低大页内存。"
	return 1
    else
	echo "预计所需大页内存：$(awk "BEGIN {printf \"%.2f\", $total_hugepages_mem_size/1048576}") GB，系统内存大小：$(awk "BEGIN {printf \"%.2f\", $mem_total_kb/1048576}") GB，系统内容不足可能导致安装结束后终端无法使用。"
    fi
}

set_numa() {
    numa_num=$(lscpu | grep "NUMA node(s)" | awk '{print $3}')
    echo "检测到 $numa_num 个 NUMA 节点。"
    
    # 处理大页内存输入
    while true; do
        read -p "请输入大页内存大小 (统一大小或以逗号分隔的各节点大小): " memory_input
    
        IFS=',' read -ra memory_array <<< "$memory_input"
    
        if [ "${#memory_array[@]}" -eq 1 ]; then
            # 用户输入统一大小
            memory_sizes=$(printf "%s," $(for ((i=0; i<numa_num; i++)); do echo -n "${memory_array[0]}"; done))
            memory_sizes=${memory_sizes%,}  # 去掉末尾的逗号
        elif [ "${#memory_array[@]}" -eq "$numa_num" ]; then
            # 用户为每个节点输入大小
            valid=true
            for mem in "${memory_array[@]}"; do
                if ! [[ "$mem" =~ ^[0-9]+$ ]]; then
                    valid=false
                    break
                fi
            done
            if $valid; then
                memory_sizes="${memory_input}"
            else
                #echo "输入无效，请确保所有值都是数字。"
    	    echo
                continue
            fi
        else
            echo "输入的节点数量与检测到的 NUMA 节点数量不符，请重新输入。"
            continue
        fi
    
        # 调用 set_numa_pages 函数进行检查
        g_hugepages="$memory_sizes"
        if set_numa_pages; then
            break
        #else
            #echo "大页内存设置无效，请重新输入。"
        fi
        echo
    done
    conf_numa=$memory_sizes
    echo "设置的大页内存为: $memory_sizes"
    echo
}

# 验证输入是否为数字的函数
is_number() {
    [[ "$1" =~ ^[0-9]+$ ]]
}

set_daemon_kni_lowpower_ltran_lstack() {
    # Prompt for daemon option
    while true; do
        read -p "是否开启daemon模式，开启为1，关闭为0；默认为1: " conf_daemon
        if [ -z "$conf_daemon" ]; then
            conf_daemon=1
            break
        elif is_number "$conf_daemon" && { [ "$conf_daemon" -eq 0 ] || [ "$conf_daemon" -eq 1 ]; }; then
            break
        else
            echo "输入无效，请输入1或0。"
        fi
    done
    
    echo
    # Prompt for KNI option
    while true; do
        read -p "是否开启kni，开启为1，关闭为0；默认为0: " conf_kni
        if [ -z "$conf_kni" ]; then
            conf_kni=0
            break
        elif is_number "$conf_kni" && { [ "$conf_kni" -eq 0 ] || [ "$conf_kni" -eq 1 ]; }; then
            break
        else
            echo "输入无效，请输入1或0。"
        fi
    done
    echo
    # Prompt for low power option
    while true; do
        read -p "是否开启低功耗模式，开启为1，关闭为0；默认为0: " conf_lowpower
        if [ -z "$conf_lowpower" ]; then
            conf_lowpower=0
            break
        elif is_number "$conf_lowpower" && { [ "$conf_lowpower" -eq 0 ] || [ "$conf_lowpower" -eq 1 ]; }; then
            break
        else
            echo "输入无效，请输入1或0。"
        fi
    done
    echo
    # Prompt for ltrancore
    while true; do
        read -p "ltran的绑核参数，参考dpdk的参数配置，此处不做参数校验；默认为0,1: " conf_ltrancore
        if [ -z "$conf_ltrancore" ]; then
            conf_ltrancore="0,1"
            break
        else
            # 这里假设不需要严格的数字验证，因为参数可能是逗号分隔的列表
            break
        fi
    done
    echo
    # Prompt for lstackcore
    while true; do
        read -p "lstack的绑核参数，同--ltrancore，默认为2: " conf_lstackcore
        if [ -z "$conf_lstackcore" ]; then
            conf_lstackcore="2"
            break
        else
            # 同样假设不需要严格的数字验证
            break
        fi
    done
}

save_config() {
    json_content=$(cat <<EOF
{
    "nic": "$conf_nic",
    "numa": "$conf_numa",
    "daemon": "$conf_daemon",
    "kni": "$conf_kni",
    "lowpower": "$conf_lowpower",
    "ltrancore": "$conf_ltrancore",
    "lstackcore": "$conf_lstackcore"
}
EOF
)
    echo "$json_content" > "$CONFIG_FILE"
    echo
    echo "参数已保存到 $CONFIG_FILE 文件中。"
}

check_config() {
    if [ -f "$CONFIG_FILE" ]; then
        echo "检测到现有的配置文件："
        cat "$CONFIG_FILE"
    
        while true; do
            read -p "是否使用此默认配置进行安装？(y/n): " use_default
            case $use_default in
                [Yy]* )
                    echo "使用默认配置进行安装。"
                    
                    # 使用参数执行命令
                    ./gazelle_setup.sh --nic "$conf_nic" --numa "$conf_numa" --daemon "$conf_daemon" --kni "$conf_kni" --lowpower "$conf_lowpower" --ltrancore "$conf_ltrancore" --lstackcore "$conf_lstackcore" > setup.log 2>&1
                    exit 0
                    ;;
                [Nn]* )
                    echo "不使用默认配置，继续手动配置。"
                    break
                    ;;
                * ) echo "请输入 y 或 n。";;
            esac
        done
    fi
    echo
}

start_install() {
    command="./gazelle_setup.sh --nic $conf_nic --numa $conf_numa --daemon $conf_daemon --kni $conf_kni --lowpower $conf_lowpower --ltrancore $conf_ltrancore --lstackcore $conf_lstackcore"
    
    # Confirm and execute the command
    echo
    echo "即将执行以下命令进行安装: $command"
    read -p "确认执行吗？ (y/n): " confirm
    
    if [ -z "$confirm" ] || [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
        # 执行命令并将所有输出重定向到日志文件
        eval $command > setup.log 2>&1
    
        # 检查命令的退出状态
        if [ $? -ne 0 ]; then
            echo "安装失败。错误信息如下："
            grep -i "error" setup.log
    	echo "更多详细日志信息储存在setup.log中！"
        else
            echo "安装完成！"
        fi
    else
        echo "操作已取消。"
    fi
}

echo
echo "欢迎使用 Gazelle 安装脚本"
echo

check_interface_status

while true; do
    echo "请选择操作:"
    echo "1) 安装Gazelle"
    echo "2) 退出Gazelle"
    echo "3) 查看帮助"
    read -p "请输入选项 (1/2/3): " choice
    if [ "$choice" = "1" ] || [ "$choice" = "2" ]; then
        break
    else
        print_help
    fi
done

if [ "$choice" = "1" ]; then
    check_config
    set_interface
    set_numa
    set_daemon_kni_lowpower_ltran_lstack
    save_config
    start_install
    sh lstack_setup.sh
fi

if [ "$choice" = "2" ]; then
  ./gazelle_exit.sh  
  echo "已退出Gazelle！"
fi
