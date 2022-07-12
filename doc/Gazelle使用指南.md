# Gazelle使用指南

## 安装
配置openEuler的yum源，直接使用yum命令安装
```sh
#dpdk >= 21.11-2
yum install dpdk
yum install libconfig
yum install numactl
yum install libboundscheck
yum install libpcap
yum install gazelle
```

## 使用方法
配置运行环境，使用Gazelle加速应用程序步骤如下：
### 1. 使用root权限安装ko
根据实际情况选择使用ko，提供虚拟网口、绑定网卡到用户态功能。  
若使用虚拟网口功能，则使用rte_kni.ko
``` sh
modprobe rte_kni carrier="on"
```
网卡从内核驱动绑为用户态驱动的ko，根据实际情况选择一种
``` sh
#若IOMMU能使用
modprobe vfio-pci

#若IOMMU不能使用，且VFIO支持noiommu
modprobe vfio enable_unsafe_noiommu_mode=1
modprobe vfio-pci

#其它情况
modprobe igb_uio
```


### 2. dpdk绑定网卡
将网卡绑定到步骤1选择的驱动。为用户态网卡驱动提供网卡资源访问接口。
``` sh
#使用vfio-pci
dpdk-devbind -b vfio-pci enp3s0 

#使用igb_uio
dpdk-devbind -b igb_uio enp3s0
```

### 3. 大页内存配置
Gazelle使用大页内存提高效率。使用root权限配置系统预留大页内存，可选用任意页大小。因每页内存都需要一个fd，使用内存较大时，建议使用1G的大页，避免占用过多fd。  
根据实际情况，选择一种页大小，配置足够的大页内存即可。配置大页操作如下： 
``` sh
#配置2M大页内存：在node0上配置 2M * 1024 = 2G
echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages

#配置1G大页内存：在node0上配置1G * 5 = 5G
echo 5 > /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages

#查看配置结果
grep Huge /proc/meminfo
```

### 4. 挂载大页内存  
创建两个目录，分别给lstack的进程、ltran进程访问大页内存使用。操作步骤如下：  
``` sh
mkdir -p /mnt/hugepages
mkdir -p /mnt/hugepages-2M
chmod -R 700 /mnt/hugepages
chmod -R 700 /mnt/hugepages-2M
mount -t hugetlbfs nodev /mnt/hugepages -o pagesize=2M
mount -t hugetlbfs nodev /mnt/hugepages-2M -o pagesize=2M
```

### 5. 应用程序使用Gazelle
有两种使用Gazelle方法，根据需要选择其一  
- 重新编译应用程序，链接Gazelle的库  
修改应用makefile文件链接liblstack.so，示例如下：
```
#makefile中添加Gazelle的Makefile
-include /etc/gazelle/lstack.Makefile

#编译添加LSTACK_LIBS变量
gcc test.c -o test ${LSTACK_LIBS}
```

- 使用LD_PRELOAD加载Gazelle的库  
GAZELLE_BIND_PROCNAME环境变量指定进程名，LD_PRELOAD指定Gazelle库路径
```
GAZELLE_BIND_PROCNAME=test LD_PRELOAD=/usr/lib64/liblstack.so ./test
```

### 6. 配置文件  
- lstack.conf用于指定lstack的启动参数，默认路径为/etc/gazelle/lstack.conf, 配置文件参数如下  

|选项|参数格式|说明|
|:---|:---|:---|
|dpdk_args|--socket-mem（必需）<br>--huge-dir（必需）<br>--proc-type（必需）<br>--legacy-mem<br>--map-perfect<br>等|dpdk初始化参数，参考dpdk说明|
|use_ltran| 0/1 | 是否使用ltran |
|listen_shadow| 0/1 | 是否使用影子fd监听，单个listen线程多个协议栈线程时使用 |
|num_cpus|"0,2,4 ..."|lstack线程绑定的cpu编号，编号的数量为lstack线程个数(小于等于网卡多队列数量)。可按NUMA选择cpu|
|num_wakeup|"1,3,5 ..."|wakeup线程绑定的cpu编号，编号的数量为wakeup线程个数，与lstack线程的数量保持一致。与numcpus选择对应NUMA的cpu。不配置则为不使用唤醒线程|
|low_power_mode|0/1|是否开启低功耗模式，暂不支持|
|kni_swith|0/1|rte_kni开关，默认为0。只有不使用ltran时才能开启|
|host_addr|"192.168.xx.xx"|协议栈的IP地址，必须和redis-server配置<br>文件里的“bind”字段保存一致。|
|mask_addr|"255.255.xx.xx"|掩码地址|
|gateway_addr|"192.168.xx.1"|网关地址|
|devices|"aa:bb:cc:dd:ee:ff"|网卡通信的mac地址，需要与ltran.conf的bond_macs配置一致|


lstack.conf示例：
``` conf
dpdk_args=["--socket-mem", "2048,0,0,0", "--huge-dir", "/mnt/hugepages-2M", "--proc-type", "primary", "--legacy-mem", "--map-perfect"]

use_ltran=1
kni_switch=0

low_power_mode=0

num_cpus="2,22"
num_wakeup="3,23"

host_addr="192.168.1.10"
mask_addr="255.255.255.0"
gateway_addr="192.168.1.1"
devices="aa:bb:cc:dd:ee:ff"
```

- ltran.conf用于指定ltran启动的参数，默认路径为/etc/gazelle/ltran.conf。使用ltran时，lstack.conf内配置use_ltran=1,配置参数如下：  

|功能分类|选项|参数格式|说明|
|:---|:---|:---|:---|
|kit|forward_kit|"dpdk"|指定网卡收发模块。<br>保留字段，目前未使用。|
||forward_kit_args|-l<br>--socket-mem(必需)<br>--huge-dir(必需)<br>--proc-TYPE(必需)<br>--legacy-mem(必需)<br>--map-perfect(必需)<br>等|dpdk初始化参数，参考dpdk说明。<br>注：--map-perfect为扩展特性，用于防止dpdk占用多余的地址空间，保证ltran有额外的地址空间分配给lstack。|
|kni|kni_switch|0/1|rte_kni开关，默认为0|
|dispatcher|dispatch_max_clients|n|ltran支持的最大client数。<br>1、多进程单线程场景，支持的lstack实例数不大于32，每lstack实例有1个网络线程<br>2、单进程多线程场景，支持的1个lstack实例，lstack实例的网络线程数不大于32|
||dispatch_subnet|192.168.xx.xx|子网掩码，表示ltran能识别的IP所在子网网段。参数为样例，子网按实际值配置。|
||dispatch_subnet_length|n|子网长度，表示ltran能识别的子网长度，例如length为4时，192.168.1.1-192.168.1.16|
|bond|bond_mode|n|bond模式，目前只支持Active Backup(Mode1)，取值为1|
||bond_miimon|n|bond链路监控时间，单位为ms，取值范围为1到2^64 - 1 - (1000 * 1000)|
||bond_ports|"0xaa"|使用的dpdk网卡，0x1表示第一块|
||bond_macs|"aa:bb:cc:dd:ee:ff"|绑定的网卡mac地址，需要跟kni的mac地址保持一致|
||bond_mtu|n|最大传输单元，默认是1500，不能超过1500，最小值为68，不能低于68|

ltran.conf示例：
``` conf
forward_kit_args="-l 0,1 --socket-mem 1024,0,0,0 --huge-dir /mnt/hugepages --proc-type primary --legacy-mem --map-perfect --syslog daemon"
forward_kit="dpdk"

kni_switch=0

dispatch_max_clients=30
dispatch_subnet="192.168.1.0"
dispatch_subnet_length=8

bond_mode=1
bond_mtu=1500
bond_miimon=100
bond_macs="aa:bb:cc:dd:ee:ff"
bond_ports="0x1"

tcp_conn_scan_interval=10
```
### 7. 启动应用程序
- 启动ltran进程  
单进程且网卡支持多队列，则直接使用网卡多队列分发报文到各线程，不启动ltran进程，lstack.conf的use_ltran配置为0.  
启动ltran时不使用-config-file指定配置文件，则使用默认路径/etc/gazelle/ltran.conf
``` sh
ltran --config-file ./ltran.conf
```
- 启动应用程序  
启动应用程序前不使用环境变量LSTACK_CONF_PATH指定配置文件，则使用默认路径/etc/gazelle/lstack.conf
``` sh
export LSTACK_CONF_PATH=./lstack.conf
LD_PRELOAD=/usr/lib64/liblstack.so  GAZELLE_BIND_PROCNAME=redis-server redis-server redis.conf
```

### 8. API
Gazelle wrap应用程序POSIX接口，应用程序无需修改代码。

### 9. 调测命令
- 不使用ltran模式时不支持gazellectl ltran xxx命令，以及lstack -r命令
```
Usage: gazellectl [-h | help]
  or:  gazellectl ltran  {quit | show} [LTRAN_OPTIONS] [time]
  or:  gazellectl lstack show {ip} [LSTACK_OPTIONS] [time]

  quit            ltran process exit

  where  LTRAN_OPTIONS :=
                  show ltran all statistics
  -r, rate        show ltran statistics per second
  -i, instance    show ltran instance register info
  -b, burst       show ltran NIC packet len per second
  -l, latency     show ltran latency

  where  LSTACK_OPTIONS :=
                  show lstack all statistics
  -r, rate        show lstack statistics per second
  -s, snmp        show lstack snmp
  -c, connetct    show lstack connect
  -l, latency     show lstack latency

  [time]          measure latency time default 1S
```

### 10. 使用注意
#### 1. dpdk配置文件的位置
如果是root用户，dpdk启动后的配置文件将会放到/var/run/dpdk目录下;
如果是非root用户，dpdk配置文件的路径将由环境变量XDG_RUNTIME_DIR决定；
- 如果XDG_RUNTIME_DIR为空，dpdk配置文件放到/tmp/dpdk目录下；
- 如果XDG_RUNTIME_DIR不为空，dpdk配置文件放到变量XDG_RUNTIME_DIR下；
- 注意有些机器会默认设置XDG_RUNTIME_DIR

## 约束限制

使用 Gazelle 存在一些约束限制：
#### 功能约束
- 不支持accept阻塞模式或者connect阻塞模式。
- 最多支持1500个TCP连接。
- 当前仅支持TCP、ICMP、ARP、IPv4 协议。
- 在对端ping Gazelle时，要求指定报文长度小于等于14000B。
- 不支持使用透明大页。
- ltran不支持使用多种类型的网卡混合组bond。
- ltran的bond1主备模式，只支持链路层故障主备切换（例如网线断开），不支持物理层故障主备切换（例如网卡下电、拔网卡）。
- 虚拟机网卡不支持多队列。  
#### 操作约束
- 提供的命令行、配置文件默认root权限。非root用户使用，需先提权以及修改文件所有者。
- 将用户态网卡绑回到内核驱动，必须先退出Gazelle。
- 大页内存不支持在挂载点里创建子目录重新挂载。
- ltran需要最低大页内存为1GB。
- 每个应用实例协议栈线程最低大页内存为800MB 。
- 仅支持64位系统。
- 构建x86版本的Gazelle使用了-march=native选项，基于构建环境的CPU（Intel® Xeon® Gold 5118 CPU @ 2.30GHz指令集进行优化。要求运行环境CPU支持 SSE4.2、AVX、AVX2、AVX-512 指令集。
- 最大IP分片数为10（ping 最大包长14790B），TCP协议不使用IP分片。
- sysctl配置网卡rp_filter参数为1，否则可能不按预期使用Gazelle协议栈，而是依然使用内核协议栈。
- 不使用ltran模式，KNI网口不可配置只支持本地通讯使用，且需要启动前配置NetworkManager不管理KNI网卡。
- 虚拟KNI网口的IP及mac地址，需要与lstack.conf配置文件保持一致 。

## 风险提示
Gazelle可能存在如下安全风险，用户需要根据使用场景评估风险。
  
**共享内存**  
- 现状  
  大页内存 mount 至 /mnt/hugepages-2M 目录，链接 liblstack.so 的进程初始化时在 /mnt/hugepages-2M 目录下创建文件，每个文件对应 2M 大页内存，并 mmap 这些文件。ltran 在收到 lstask 的注册信息后，根据大页内存配置信息也 mmap 目录下文件，实现大页内存共享。
  ltran 在 /mnt/hugepages 目录的大页内存同理。
- 当前消减措施
  大页文件权限 600，只有 OWNER 用户才能访问文件，默认 root 用户，支持配置成其它用户； 
  大页文件有 DPDK 文件锁，不能直接写或者映射。
- 风险点 
  属于同一用户的恶意进程模仿DPDK实现逻辑，通过大页文件共享大页内存，写破坏大页内存，导致Gazelle程序crash。建议用户下的进程属于同一信任域。

**流量限制**  
Gazelle没有做流量限制，用户有能力发送最大网卡线速流量的报文到网络，可能导致网络流量拥塞。

**进程仿冒**  
合法注册到ltran的两个lstack进程，进程A可仿冒进程B发送仿冒消息给ltran，修改ltran的转发控制信息，造成进程B通讯异常，进程B报文转发给进程A信息泄露等问题。建议lstack进程都为可信任进程。
