#!/bin/bash
#Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
#Description: ltran quit and clear the environment

PROJ_ROOT=$(
    cd $(dirname $0)/
    pwd
)
source $PROJ_ROOT/gazelle_common.sh

if [ "$1"x = "-hx" ] || [ "$1"x = "--helpx" ]; then
    echo "$0 :uninstall gazelle deployment!"
    exit 0
fi

cron_cmd="gazelle_crontab.sh"

del_gazelle_crontab_task() {
    cron_num=$(crontab -l | wc -l)
    if [ ${cron_num=} == 1 ]; then
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

del_gazelle_crontab_task
crond_pid=$(ps -ef | grep gazelle_crontab.sh | grep -v grep | awk '{print $2}')
if [ -n "$crond_pid" ]; then
    msg_show "kill crond task"
    kill -9 $crond_pid
fi
kill_ltran
nic_recover
if [ $? -ne 0 ]; then
    msg_err "recover failed, check the nic name or config file!"
    exit 1
else
    msg_show "successfully recover the nic"
fi
clear_huge_pages
if [ $? -ne 0 ]; then
    msg_err "clear env failed, exit gazelle..."
else
    msg_show "clear env successfully, exit gazelle..."
fi
remove_kni_module
remove_igb_uio_module

local_ipAddr=$(sudo grep ipAddr $PARAM_PATH | awk '-F[=]' '{print $2}')
dpdk_path="gazelle_${local_ipAddr}"
sudo rm -fr /etc/NetworkManager/conf.d/gazelle.conf
sudo rm -fr /var/run/dpdk/${dpdk_path}
sudo rm -fr /var/run/dpdk/rte
sudo rm -fr /tmp/dpdk/${dpdk_path}
sudo rm -fr /tmp/dpdk/rte
sudo rm -fr /var/run/gazelle
