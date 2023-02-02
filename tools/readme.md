# 一键部署脚本使用
提供gazelle_setup脚本，用于快速自动化部署gazelle运行环境，需要gazelle_setup.sh、gazelle_common.sh、gazelle_exit.sh、gazelle_crontab.sh 拷贝到/usr/bin 目录下。

## 一键部署脚本执行示例：
gazelle_setup.sh –i/--nic eth0 –n/--numa 1024,1024 –d/--daemon 1/0 –k/--kni 1/0 –l/--lowpower 1/0 --ltrancore 0,1 --lstackcore 2-3
参数描述：
+ -i/--nic：设置待绑定网卡，此参数必须配置，且网卡需要有ip、路由和网关等必须参数，否则会读取配置失败，必选。
+ -n/--numa：lstack大页内存（不包括ltran的，ltran默认为1024M，setup脚本不对其做修改），根据numa节点配置，并用","(英文的逗号)分离，这里需要根据系统环境内存配置对应的大小，默认为1024， 可选。
+ -d/--daemon：是否开启deamon模式，开启为1，关闭为0；默认为1，可选。
+ -k/--kni：是否开启kni，开启为1，关闭为0；默认为0，可选。
+ -l/--lowpower：是否开启低功耗模式，开启为1，关闭为0；默认为0，可选。
+ --ltrancore：ltran的绑核参数，参考dpdk的参数配置，此处不做参数校验；默认为0,1，可选。
+ --lstackcore：lstack的绑核参数，同--ltrancore，默认为2，可选。

## 一键退出脚本执行实例：
gazelle_exit.sh

## 说明
+ 默认配置文件的目录为：/etc/gazelle
+ 部署脚本会启动ltran进程
+ 若启动了ltran的守护任务（gazelle_setup.sh指定了 -d/--daemon 1），那么在杀死ltran之后，守护任务仍会将ltran拉起，所以此时若要完全退出ltran，需要执行gazelle_exit.sh。
