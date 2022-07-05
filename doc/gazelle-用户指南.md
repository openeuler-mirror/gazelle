# gazelle-用户指南

## 1 简介

EulerOS提供了利用Gazelle runtime优化数据库服务性能的完整解决方案，Gazelle
runtime基于bypass内核的架构设计，能够提供更高性能运行环境，优化服务软件性
能，可以很好地满足产品的性能需求。
本文主要介绍Gazelle软件如何安装使用。

## 2 安装软件包，编译应用程序（以redis 为例）

在使用之前，需要安装Gazelle软件包。

### 操作步骤

Gazelle是高性能用户态协议栈软件包，使用如下命令安装Gazelle软件包：

```
yum install gazelle
```

### 安装正确性验证

1. 安装完成后，使用“rpm -qa | grep -E gazelle”命令确认是否已经正确安装。示例如下：

如果已正确安装则结果显示如下：
```
gazelle-1.0.0-h1.eulerosv2r10.aarch64
```

  2. 确认以下dpdk组件是否存在：
```
rpm -ql dpdk | grep igb_uio
/usr/share/dpdk
/usr/share/dpdk/usertools/dpdk-devbind.py
```

  3. 确认以下Gazelle组件是否存在：

```
/usr/bin/gazellectl
/usr/bin/ltran
/usr/lib64/liblstack.so
/etc/gazelle/ltran.conf
/etc/gazelle/lstack.conf
/etc/gazelle/lstack.Makefile
```

### 链接Gazelle编译redis-server

1. 获取开源redis代码，更改redis/src/Makefile文件，使其链接lstack，示例如下：

```
diff --git a/src/Makefile b/src/Makefile
index 4b2a31c..92fa17d 100644
--- a/src/Makefile
+++ b/src/Makefile
@@ -72,6 +72,10 @@ endif
 # Override default settings if possible
 -include .make-settings

+ifdef USE_GAZELLE
+    -include /etc/gazelle/lstack.Makefile
+endif
+
 FINAL_CFLAGS=$(STD) $(WARN) $(OPT) $(DEBUG) $(CFLAGS) $(REDIS_CFLAGS)
 FINAL_LDFLAGS=$(LDFLAGS) $(REDIS_LDFLAGS) $(DEBUG)
 FINAL_LIBS=-lm
@@ -225,7 +229,7 @@ endif

 # redis-server
 $(REDIS_SERVER_NAME): $(REDIS_SERVER_OBJ)
-   $(REDIS_LD) -o $@ $^ ../deps/hiredis/libhiredis.a ../deps/lua/src/liblua.a $(FINAL_LIBS)
+   $(REDIS_LD) -o $@ $^ ../deps/hiredis/libhiredis.a ../deps/lua/src/liblua.a $(FINAL_LIBS) $(LSTACK_LIBS)
```

2. 编译redis：

  ```
  localhost:/euler/zyk/serverless/lredis/src # make distclean
  localhost:/euler/zyk/serverless/lredis/src # make USE_GAZELLE=1 -j32
  ```

#### 注意

除了上述Gazelle发布的软件包以外，Gazelle还依赖libsecurec，libconfig，numactl和libpcap库，生产环境需确认安装libsecurec，libconfig，numactl和libpcap。

 支持LD_PRELOAD方式免编译使用gazelle，可跳过编译应用程序步骤。

## 3 设置配置文件（以redis为例）

  安装完软件包后，运行Gazelle服务需要设置必要的配置文件。

  #### lstack.conf

  lstack.conf主要用于传递lstack初始化所需要的参数，Gazelle发布件会包括lstack.conf供用户参考，路径为**/etc/gazelle/lstack.conf**，配置文件格式如下：

| **选项**       | **参数格式**                                                 | **说明**                                                     |
| -------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| dpdk_args      | -l--socket-mem（必需）--huge-dir（必需）--proc-type（必需）等 | dpdk初始化参数，参考dpdk说明。                               |
| low_power_mode | 0/1                                                          | 低功耗模式开关。                                             |
| num_cpus       | n                                                            | 共享队列数量，该值目前不生效，默认为1。保留字段，目前未使用。 |
| host_addr      | "192.168.xx.xx"                                              | 协议栈的IP地址，必须和redis-server配置。文件里的“bind”字段保存一致。 |
| mask_addr      | "255.255.xx.xx"                                              | 掩码地址（必填）。                                           |
| gateway_addr   | "192.168.xx.1"                                               | 网关地址（必填）。                                           |
| devices        | "aa:bb:cc:dd:ee:ff"                                          | 网卡通信的mac地址，需要与ltran.conf中的bond_macs配置成一样（必填）。 |

  

#### 示例

```
dpdk_args=["-l", "2", "--socket-mem", "2048,0,0,0","--huge-dir", "/mnt/hugepages-2M", "--proc-type", "primary"]
num_cpus=1

low_power_mode=0

host_addr="192.168.1.10"
mask_addr="255.255.255.0"
gateway_addr="192.168.1.1"
devices="aa:bb:cc:dd:ee:ff"
```
#### ltran.conf

  ltran.conf用于指定ltran启动的参数，Gazelle发布件会包括ltran.conf供用户参考，路径为**/etc/gazelle/ltran.conf**，配置文件格式如下：

| **功能分类**           | **选项**                                                     | **参数格式**                                                 | **说明**                                                     |
| ---------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| kit                    | forward_kit                                                  | "dpdk"                                                       | 指定网卡收发模块，当前使用dpdk。                             |
| forward_kit_args       | -l--socket-mem （必需）--huge-dir（必需）--proc-type（必需）--legacy-mem （必需）--map-perfect （必需）等 | dpdk初始化参数，参考dpdk说明。注：--map-perfect为扩展特性，用于防止dpdk占用多余的地址空间，保证有额外的地址空间分配给lstack。 |                                                              |
| kni                    | kni_switch                                                   | 0/1                                                          | rte_kni开关，默认为0。                                       |
| dispatcher             | dispatch_max_clients                                         | n                                                            | ltran支持的最大client数。多进程单线程场景，支持lstack实例数不大于32，每lstack实例有1个网络线程。单进程多线程场景，支持1个lstack实例，lstack实例的网络线程数不大于32。 |
| dispatch_subnet        | 192.168.xx.xx                                                | 子网掩码，表示ltran能识别的IP所在子网网段。参数为样例，子网按实际值配置。 |                                                              |
| dispatch_subnet_length | n                                                            | 子网长度，表示ltran能识别的子网长度，例如length为4时，192.168.1.1-192.168.1.16。 |                                                              |
| bond                   | bond_mode                                                    | n                                                            | bond模式，目前只支持Active Backup（Mode1），取值为1。        |
| bond_miimon            | n                                                            | bond链路监控时间，单位为ms，取值范围为1到2^64 - 1 - (1000 * 1000)。 |                                                              |
| bond_ports             | "0xaa"                                                       | 使用的dpdk网卡，0x1表示第一块。                              |                                                              |
| bond_macs              | "aa:bb:cc:dd:ee:ff"                                          | 绑定的网卡mac地址。                                          |                                                              |
| bond_mtu               | n                                                            | 最大传输速度，默认是1500，不能超过1500，不能低于68。         |                                                              |
| 老化                   | tcp_conn_scan_interval                                       | n                                                            | ltran老化conn、sock表项间隔，默认为10。                      |

  

#### 示例

```
forward_kit="dpdk"
forward_kit_args="-l 0,1 --socket-mem 1024,0,0,0 --huge-dir /mnt/hugepages --proc-type primary --legacy-mem --map-perfect --syslog daemon"

kni_switch=0

dispatch_subnet="192.168.1.0"
dispatch_subnet_length=8
dispatch_max_clients=30

bond_mode=1
bond_miimon=100
bond_mtu=1500
bond_ports="0x1"
bond_macs="aa:bb:cc:dd:ee:ff"

tcp_conn_scan_interval=10
```

#### redis.conf

  redis.conf为redis服务的配置文件，可以参考开源的配置文件，需要注意的是，redis.conf侦听的ip必须和其使用的lstack.conf里面的host_addr值保持一致。

## 4 环境初始化

配置文件完成后，需要配置大页、插入igb_uio.ko、绑定dpdk网卡等环境初始化工作才可以运行Gazelle服务。

**说明：igb_uio.ko依赖于uio.ko，需要用户先确保已安装uio.ko模块。**

### 操作步骤

1. **配置大页内存**

   通过/sys/devices/system/node配置大页内存，示例如下：

```
[root@ARM159server usertools]# cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
1043
[root@ARM159server usertools]# echo 2048 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
[root@ARM159server usertools]# cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
2048
```

2. **ko初始化**

   需要插入ko包括igb_uio和vfio_pci，示例如下：

```
[root@ARM159server usertools]# modprobe uio
[root@ARM159server usertools]# insmod /lib/modules/4.19.90-vhulk2007.2.0.h188.eulerosv2r10.aarch64/extra/dpdk/igb_uio.ko
[root@ARM159server usertools]# modprobe vfio_pci
```

3. **绑定dpdk网卡**

   将需要通信的网卡绑定到dpdk，示例如下：

```
[root@ARM159server usertools]# dpdk-devbind.py --bind=igb_uio eth4
```

   如果是1822网卡，必须绑定vfio-pci驱动：

```
[root@ARM159server usertools]# dpdk-devbind.py --bind=vfio-pci eth4 
```

## 5 运行Gazelle

### 前提条件

- 已完成软件包的安装。
- 已设置完配置文件。
- 已初始化环境。

### 操作步骤

1. **启动ltran**

   环境初始化后可以启动ltran，示例如下：

   如果不指定--config-file，则默认使用路径/etc/gazelle/ltran.conf。

   **说明：一键部署脚本已启动ltran，若使用一键部署脚本，无需此步骤。**

```
[root@localhost deploy_open_source]# ltran --config-file /usr/share/gazelle/ltran.conf
EAL: Detected 96 lcore(s)
EAL: Detected 4 NUMA nodes
EAL: Multi-process socket /var/run/dpdk/(null)/mp_socket
EAL: Selected IOVA mode 'PA'
EAL: No free hugepages reported in hugepages-2048kB
EAL: No free hugepages reported in hugepages-2048kB
EAL: No free hugepages reported in hugepages-2048kB
EAL: No available hugepages reported in hugepages-1048576kB
EAL: Probing VFIO support...
EAL: VFIO support initialized
EAL: PCI device 0000:03:00.0 on NUMA socket 0......
EAL: Finished Process ltran_core_init.
EAL: Finished Process ctrl_thread_fn.
EAL: Finished Process client_rx_buf_init.
EAL: Runing Process forward.
```

2. **启动redis**
  

启动redis需要两个conf文件，lstack.conf用于指定lstack的初始化参数，lstack.conf可以由环境变量LSTACK_CONF_PATH指定，如果不指定，则默认使用路径/etc/gazelle/lstack.conf，redis.conf指定redis的参数，参数解释参考[ lstack.conf文件格式]，示例如下：

```
[root@localhost src]# export LSTACK_CONF_PATH=/usr/share/gazelle/lstack.conf
[root@localhost src]# ./redis-server /usr/share/gazelle/redis.conf 
INFO: posix_api_init success
using config :'/usr/share/gazelle/lstack.conf'
dpdk argv: --socket-mem 2048,0,0,0 --huge-dir /mnt/hugepages-2M -l 3 --proc-type auto 
INFO: cfg_init success
EAL: type 0, port 6379, ip 2148143737, file_prefix libnet_128.10.18.121
INFO: require base_virtaddr 0, get 0x4108000000
pid(87935) file_prefix(libnet_128.10.18.121) args: libos_mem --socket-mem 2048,0,0,0 --huge-dir /mnt/hugepages-2M -l 3 --proc-type auto --file-prefix libnet_128.10.18.121 --legacy-mem --map-perfect --base-virtaddr 4108000000 
EAL: Detected 128 lcore(s)
EAL: Detected 4 NUMA nodes
EAL: Auto-detected process type: PRIMARY
EAL: Multi-process socket /var/run/dpdk/libnet_128.10.18.121/mp_socket
EAL: Selected IOVA mode 'VA'
EAL: No free hugepages reported in hugepages-2048kB
EAL: No free hugepages reported in hugepages-2048kB
EAL: No free hugepages reported in hugepages-2048kB
EAL: No available hugepages reported in hugepages-1048576kB
EAL: Probing VFIO support...
EAL: VFIO support initialized
INFO: control_init success
PORT: hugepage_init success
PORT: tcpip_init success
PORT: ethdev_init success
PORT: create control_easy_thread success
87935:C 10 Aug 2020 08:05:11.760 # oO0OoO0OoO0Oo Redis is starting oO0OoO0OoO0Oo
87935:C 10 Aug 2020 08:05:11.760 # Redis version=5.0.8, bits=64, commit=00000000, modified=0, pid=87935, just started
87935:C 10 Aug 2020 08:05:11.760 # Configuration loaded
87935:M 10 Aug 2020 08:05:11.761 * Increased maximum number of open files to 10032 (it was originally set to 4096).
PORT: thread(87935) lcore_id(3) already init
                _._                                                  
           _.-``__ ''-._                                             
      _.-``    `.  `_.  ''-._           Redis 5.0.8 (00000000/0) 64 bit
  .-`` .-```.  ```\/    _.,_ ''-._                                   
 (    '      ,       .-`  | `,    )     Running in standalone mode
 |`-._`-...-` __...-.``-._|'` _.-'|     Port: 6379
 |    `-._   `._    /     _.-'    |     PID: 87935
  `-._    `-._  `-./  _.-'    _.-'                                   
 |`-._`-._    `-.__.-'    _.-'_.-'|                                  
 |    `-._`-._        _.-'_.-'    |           http://redis.io        
  `-._    `-._`-.__.-'_.-'    _.-'                                   
 |`-._`-._    `-.__.-'    _.-'_.-'|                                  
 |    `-._`-._        _.-'_.-'    |                                  
  `-._    `-._`-.__.-'_.-'    _.-'                                   
      `-._    `-.__.-'    _.-'                                       
          `-._        _.-'                                           
              `-.__.-'                                               

87935:M 10 Aug 2020 08:05:11.761 # WARNING: The TCP backlog setting of 511 cannot be enforced because /proc/sys/net/core/somaxconn is set to the lower value of 128.
87935:M 10 Aug 2020 08:05:11.761 # Server initialized
87935:M 10 Aug 2020 08:05:11.761 # WARNING overcommit_memory is set to 0! Background save may fail under low memory condition. To fix this issue add 'vm.overcommit_memory = 1' to /etc/sysctl.conf and then reboot or run the command 'sysctl vm.overcommit_memory=1' for this to take effect.
87935:M 10 Aug 2020 08:05:11.761 # WARNING you have Transparent Huge Pages (THP) support enabled in your kernel. This will create latency and memory usage issues with Redis. To fix this issue run the command 'echo never > /sys/kernel/mm/transparent_hugepage/enabled' as root, and add it to your /etc/rc.local in order to retain the setting after a reboot. Redis must be restarted after THP is disabled.
87935:M 10 Aug 2020 08:05:11.761 * DB loaded from disk: 0.000 seconds
87935:M 10 Aug 2020 08:05:11.761 * Ready to accept connections
```

3. 使用LD_PRELOAD方式，免编译使用用户态协议栈

   通过LD_PRELOAD方式启动benchmark_ker；

```
GAZELLE_BIND_PROCNAME=benchmark_ker GAZELLE_BIND_THREADNAME=disp LD_PRELOAD=/lib64/liblstack.so /etc/gazelle/benchmark_ker -sMode dn -pSize 0 -mSize 1024 -pdSize 1 -cFile /etc/gazelle/config.ini
```

   **说明**

   1. 不支持使用export方式单独声明LD_PRELOAD环境变量。
   2. GAZELLE_BIND_PROCNAME指定lstack绑定的进程名称；GAZELLE_BIND_THREADNAME指定lstack绑定的进程中的具体线程名，且支持字串匹配，如设置disp，表示进程中所有线程名包含disp 字串的线程都会绑定lstack。

## 6 最佳性能配置

为获得最佳的性能，Gazelle在启动时对cpu和内存配置有一定要求。最佳性能配置如下：

1. ltran运行的cpu必须与网卡在同一个numa节点上。
2. ltran是一个负责包转发的模块，其rx和tx方向是分开两个线程的，因此ltran启动时需要配置至少两个cpu，保证rx和tx线程运行在不同的cpu上（配置方法参考ltran启动章节）。
3. ltran的rx方向线程的性能对整个libnet系统的性能至关重要，尽可能保证其独占一个cluster。在目前公有云redis服务使用的环境上，每四个cpu是同一个cluster，例如0到3号cpu是同一个cluster，4到7号cpu是同一个cluster。假如ltran的rx方向线程运行在0核上，那么tx方向线程和redis尽量不要跑在1-3号cpu上。
4. 应用进程绑核可提高性能，与网卡同一个numa节点对应的核如果有空闲，应当优先绑定。
5. Gazelle的网络高性能只有在远程访问的时候才有保证，本机的tcp连接功能也支持，但如果本机有频繁的数据访问，会导致实例整体性能下降，不建议这么部署。

## 7 使用约束

1. Gazelle提供的命令行及配置文件仅root权限开源执行或修改。配置大页内存需要root用户执行操作。
2. 在将网卡绑定到igb_uio后，禁止将网卡绑回ixgbe。
3. 如果需要把Gazelle使用的网卡绑回ixgbe驱动，或者从igb_uio驱动解绑，不允许在Gazelle还在运行时执行上述操作，须先将Gazelle退出，再将执行unbind或者bind操作，否则会导致内核panic。
4. Gazelle不支持accept阻塞模式或者connect阻塞模式。
5. Gazelle最多只支持20000个链接（需要保证进程内，非网络连接的fd个数小于2000个）。
6. Gazelle协议栈当前只支持tcp、icmp、arp、ipv4，使用其他协议可能导致实例异常。
7. Gazelle不允许在一个挂载点里面创建子目录重新挂载，否则可能对大页挂载路径重复初始化，导致应用启动失败。
8. Gazelle组件自身无数据安全风险，但是依赖dpdk的共享内存管理。如果dpdk的大页内存管理机制存在安全问题，Gazelle中的共享内存有被攻击的风险。
9. 在对端使用ping命令时，要求指定报文长度小于等于14000。报文长度超过14000时行为不可预测。
10. Gazelle不支持使用透明大页。
11. 需要保证ltran的可用大页内存 >=850M。
12. 需要保证lstack实例一个网络线程的可用大页内存 >=500M。
13. Gazelle不支持32位系统使用。
14. ltran不支持使用多种类型的网卡混合组bond。
15. ltran的bond1主备模式，只支持链路层故障主备切换（例如网线断开），不支持物理层故障主备切换（例如网卡下电、拔网卡）。
16. 构建X86版本使用-march=native选项，基于构建环境的CPU（Intel® Xeon® Gold 5118 CPU @ 2.30GHz）指令集进行优化。要求运行环境CPU支持SSE4.2、AVX、AVX2、AVX-512指令集。
17. Gazelle的最大IP分片数为10（ping最大包长14790），TCP协议不使用IP分片。
18. ltran重启自恢复业务功能，只支持单进程场景。
19. LD_PRELOAD免编译方式，不支持export方式声明LD_PRELOAD环境变量。
20. gazelle_setup.sh脚本执行时，参数-i/--nic表示待绑定网卡，此参数必须配置，且网卡需要有ip、路由和网关等必须参数。
21. 非root用户执行一键部署脚本，当前仅支持sudo NOPASSWD模式。
22. 部署脚本不支持不同用户混用。
23. 部署脚本不支持并发使用。
24. 低功耗模式不涉及ltran进程。
25. 使用部署脚本时，用户不需要手动启停ltran进程，启动进程使用gazelle_setup.sh脚本，停止进程使用gazelle_exit.sh脚本。
26. ltran的用户态网卡收发机制是基于DPDK实现，其中EulerOS上DPDK包支持网卡有hinic、virtio。



## 8 升级说明

后续升级需要变更的组件包括ltran、liblstack.so、gazellectl、lstack.Makefile、lstack.conf、ltran.conf、gazelle_setup.sh、gazelle_exit.sh、gazelle_crontab.sh、gazelle_common.sh。

1. 升级Gazelle前，使用足够权限的账户，停止ltran进程、用户进程。

2. 如无接口变更，旧的lstack应用与新的lstack应用均可使用。

3. 软件包升级时，配置文件说明。

   - 软件包配置文件没有变更

     若用户已修改配置文件，保留用户修改后配置文件。

     若用户未修改配置文件，覆盖成软件包新配置文件。

   - 软件包配置文件有变更

     若用户已修改配置文件，保留用户修改后配置文件，软件包新配置文件添加.rpmnew后缀保存在同一目录。需要手动填写新的配置文件，去除后缀替换原有配置文件。

     若用户未修改配置文件，覆盖成软件包新配置文件。

   - 备份配置文件场景

     若用户修改了配置文件，删除gazelle包或者降级旧版本，配置文件添加.rpmsave后缀保存在同一目录。



## 9 调测工具

### 9.1 获取ltran统计数据说明

#### 概述

本节介绍如何使用Gazellectl工具获取中心节点ltran上的网络收发包信息。

#### 使用方法

- 获取ltran启动后，注册成功的client详细信息，如id/port/state等：

```
  gazellectl ltran show -i
```

- 获取ltran启动后，网卡以及各个client的数据收发信息：

```
  gazellectl ltran show
```

- 获取ltran启动后，网卡数据的收发的pps和bps信息：

```
  gazellectl ltran show -r
```

- 获取ltran启动后，网卡数据的接收的burst信息：

```
  gazellectl ltran show -b
```

- 获取ltran启动后，网卡数据的接收的时延信息：
```
  gazellectl ltran show -l
```

- ltran启动后，设置ltran日志等级：

```
  gazellectl ltran set loglevel {error | info | debug}
```

- 获取ltran启动后，ltran内部sock表信息：

```
  gazellectl ltran show -t socktable
```

- 获取ltran启动后，ltran内部conn表信息：

```
  gazellectl ltran show -t conntable
```

- 停止ltran进程：

```
  gazellectl ltran quit
```



### 9.2 获取Lstack统计数据说明

#### 概述

本节介绍如何使用Gazelle工具获取边缘协议栈节点lstack上的网络收发包以及协议栈连接统计信息。

**说明**

lstack作为网络协议栈底座，使用时必须指定需要获取的lstack所在进程配置的ip。

#### 使用方法

- 获取lstack启动后，client的数据收发信息：

```
  gazellectl lstack show {client_ip} 
```

- 获取lstack上，client的数据收发pps速率：

```
  gazellectl lstack show {client_ip} -r
```

- 获取lstack上的协议栈snmp统计信息：

```
  gazellectl lstack show {client_ip} -s
```

- 获取lstack上的tcp连接信息：

```
  gazellectl lstack show {client_ip} -c
```

- 获取lstack上的收包时延信息：

```
  gazellectl lstack show {client_ip} -l
```

- 设置lstack的日志信息等级:

```
  gazellectl lstack set {client_ip} loglevel {error | info | debug}
```

- 设置lstack的低功耗模式:

```
  gazellectl lstack set {client_ip} lowpower {0 | 1}1:enable lowpower mode
```
