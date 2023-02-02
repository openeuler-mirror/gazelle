#!/bin/bash
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
# Description: make ltran daemon when fail resume nic and del crontab task

PROJ_ROOT=$(
    cd $(dirname $0)/
    pwd
)
source $PROJ_ROOT/gazelle_common.sh

if [ "$1"x != 1x ] && [ "$1"x != 0x ]; then
    echo "input param error, please use gazelle_setup.sh or gazelle_exit.sh"
    exit 0
fi

ltran_conf=$(sudo grep ltran $PARAM_PATH | awk '{print $2}')
cron_cmd="gazelle_crontab.sh"
daemon_on="1"
check_interval=1
min_sec=$(date +%-S)

del_gazelle_crontab_task() {
    cron_num=$(crontab -l | wc -l)
    if [ ${cron_num} == 1 ]; then
        crontab -l | grep ${cron_cmd} > /dev/null
        if [ $? == 0 ]; then
            msg_show "del crontab"
            crontab -r
            return 0
        fi
    fi

    msg_show "del gazelle crontab task"
    crontab -l > ./gazelle_crontab_tmp && sed -i "/${cron_cmd}/d" ./gazelle_crontab_tmp && crontab ./gazelle_crontab_tmp && rm -fr ./gazelle_crontab_tmp
    return 0
}

check_daemon_ltran() {
    if [ -z $ltran_conf ]; then
        return 1
    fi

    local kni_switch=$(sudo grep -w kni_switch $CONF_DIR/ltran.conf | awk '{print $3}')
    check_ltran && return 0
    pkill -9 ltran
    local i
    for ((i = 0; i < 3; i++)); do
        XDG_RUNTIME_DIR=/tmp nohup /usr/bin/ltran ${ltran_conf} > /dev/null 2>&1 &
        sleep 3
        check_ltran
        if [ $? -eq 0 ]; then
            if [ $kni_switch = 1 ]; then
                configure_nic "usr"
                if [ $? -eq 0 ]; then
                    msg_show "configure the kni successfully"
                    return 0
                else
                    return 1
                fi
            else
                return 0
            fi
        else
            msg_show "start ltran failed!"
        fi
    done
    sleep 3
    return 1
}

# check if another daemon task is running
min_sec=$((60 - $min_sec))
mindiv=$(($min_sec / $check_interval))

for ((i = 0; i < ${mindiv}; i++)); do
    if [[ $# == 1 && $1 == ${daemon_on} ]]; then
        check_daemon_ltran
    else
        check_ltran
    fi
    if [ $? -eq 1 ]; then
        del_gazelle_crontab_task
        nic_recover
        clear_huge_pages
        remove_kni_module
        remove_igb_uio_module
        self_pid=$$
        crond_pid=$(ps -ef | grep gazelle_crontab.sh | grep -v grep | grep -v $self_pid | awk '{print $2}')
        if [ -n "$crond_pid" ]; then
            kill -9 $crond_pid
        fi
        break
    fi
    sleep $check_interval
done
