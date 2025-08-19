# Gazelle用户指南

## 简介

Gazelle是一款高性能用户态协议栈。它基于DPDK在用户态直接读写网卡报文，共享大页内存传递报文，使用轻量级LwIP协议栈。能够大幅提高应用的网络I/O吞吐能力。专注于数据库网络性能加速，如MySQL、redis等。

- 高性能

  报文零拷贝，无锁，灵活scale-out，自适应调度。

- 通用性

  完全兼容POSIX，零修改，适用不同类型的应用。

  单进程且网卡支持多队列时，只需使用liblstack.so有更短的报文路径。

## 安装

配置openEuler的yum源，直接使用yum命令安装

```sh
yum install dpdk
yum install libconfig
yum install numactl
yum install libboundscheck
yum install libpcap
yum install gazelle
```

>说明:  
dpdk >= 21.11-2

## 使用方法

配置运行环境，使用Gazelle加速应用程序步骤如下：

### 1. 使用root权限安装ko

根据实际情况选择使用ko，提供绑定网卡到用户态功能。  
网卡从内核驱动绑为用户态驱动的ko，根据实际情况选择一种。

```sh
#若IOMMU能使用
modprobe vfio-pci

#若IOMMU不能使用，且VFIO支持noiommu
modprobe vfio enable_unsafe_noiommu_mode=1
modprobe vfio-pci

#其他情况
modprobe igb_uio
```

>说明:  
可根据机器BIOS配置，查看是否使能IOMMU。

### 2. dpdk绑定网卡

将网卡绑定到步骤1选择的驱动。为用户态网卡驱动提供网卡资源访问接口。

```sh
#使用vfio-pci
dpdk-devbind -b vfio-pci enp3s0

#使用igb_uio
dpdk-devbind -b igb_uio enp3s0
```

### 3. 大页内存配置

Gazelle使用大页内存提高效率。使用root权限配置系统预留大页内存，可选用任意页大小。因每页内存都需要一个fd，使用内存较大时，建议使用1G的大页，避免占用过多fd。  
根据实际情况，选择一种页大小，配置足够的大页内存即可。配置大页操作如下：

```sh
#配置2M大页内存：在node0上配置 2M * 1024 = 2G
echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages

#配置1G大页内存：在node0上配置1G * 5 = 5G
echo 5 > /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages
```

>说明：  
cat查询实际预留页个数，连续内存不足时可能比预期少

### 4. 挂载大页内存  

创建目录，给lstack的进程访问大页内存使用。操作步骤如下：  

```sh
mkdir -p /mnt/hugepages-lstack
chmod -R 700 /mnt/hugepages-lstack

mount -t hugetlbfs nodev /mnt/hugepages-lstack -o pagesize=2M
```

### 5. 应用程序使用Gazelle

有两种使用Gazelle方法，根据需要选择其一  

- 重新编译应用程序，替换sockets接口  

```sh
#makefile中添加Gazelle的Makefile
-include /etc/gazelle/lstack.Makefile

#编译添加LSTACK_LIBS变量
gcc test.c -o test ${LSTACK_LIBS}
```

- 使用LD_PRELOAD加载Gazelle库

  GAZELLE_BIND_PROCNAME环境变量指定进程名，LD_PRELOAD指定Gazelle库路径。

  ```sh
  GAZELLE_BIND_PROCNAME=test LD_PRELOAD=/usr/lib64/liblstack.so ./test
  ```

- 使用GAZELLE_THREAD_NAME指定Gazelle绑定的线程名

  同一进程中的多个线程中，仅有某个线程满足gazelle的使用条件时，可以使用GAZELLE_THREAD_NAME来指定仅由对应的线程名使用gazelle，而其他线程走内核态协议栈。

  ```sh
  GAZELLE_BIND_PROCNAME=test GAZELLE_THREAD_NAME=test_thread LD_PRELOAD=/usr/lib64/liblstack.so ./test
  ```

### 6. 配置文件  

- lstack.conf用于指定lstack的启动参数，默认路径为/etc/gazelle/lstack.conf, 配置文件参数如下  

|选项|参数格式|说明|
|:---|:---|:---|
|dpdk_args|--socket-mem（必需）<br>--huge-dir（必需）<br>--proc-type（必需）<br>--legacy-mem<br>--map-perfect<br>-d|dpdk初始化参数，参考dpdk说明<br>--map-perfect为扩展特性，用于防止dpdk占用多余的地址空间，保证有额外的地址空间分配给lstack。<br>-d参数加载指定so库文件|
|listen_shadow| 0/1 | 是否使用影子fd监听。单listen线程，多协议栈线程时是能|
|use_ltran| 0/1 | 是否使用ltran ，功能已衰退，不再支持|
|num_cpus|"0,2,4 ..."|lstack线程绑定的cpu编号，编号的数量为lstack线程个数(小于等于网卡多队列数量)。可按NUMA选择cpu|
|low_power_mode|0/1|是否开启低功耗模式，暂不支持|
|kni_switch|0/1|rte_kni开关，默认为0。功能已衰退，不再支持|
|unix_prefix|"string"|gazelle进程间通信使用的unix socket文件前缀字符串，默认为空，和需要通信的ltran.conf的unix_prefix或gazellectl的-u参数配置一致。不能含有特殊字符，最大长度为128。|
|host_addr|"192.168.xx.xx"|协议栈的IP地址，也是应用程序的IP地址|
|mask_addr|"255.255.xx.xx"|掩码地址|
|gateway_addr|"192.168.xx.1"|网关地址|
|devices|"aa:bb:cc:dd:ee:ff"|网卡通信的mac地址，在bond1模式下作为bond的主网口|
|app_bind_numa|0/1|应用的epoll和poll线程是否绑定到协议栈所在的numa，缺省值是1，即绑定|
|send_connect_number|4|设置为正整数，表示每次协议栈循环中发包处理的连接个数|
|read_connect_number|4|设置为正整数，表示每次协议栈循环中收包处理的连接个数|
|rpc_number|4|设置为正整数，表示每次协议栈循环中rpc消息处理的个数|
|nic_read_num|128|设置为正整数，表示每次协议栈循环中从网卡读取的数据包的个数|
|bond_mode|-1|设置组bond，当前支持两个网口组bond模式，默认值-1关闭bond，当前支持bond1/4/6|
|bond_slave_mac|"aa:bb:cc:dd:ee:ff;AA:BB:CC:DD:EE:FF"|设置组bond网口的mac地址信息，以;分隔|
|bond_miimon|10|设置bond模式的监听间隔，默认值10，取值范围0~1500|
|udp_enable|0/1|是否开启udp功能，默认值1开启|
|nic_vlan_mode|-1|是否开启vlan模式，默认值-1关闭，取值范围-1~4095，0和4095是业界通用预留id无实际效果|
|tcp_conn_count|1500|tcp的最大连接数，该参数乘以mbuf_count_per_conn是初始化时申请的mbuf池大小，配置过小会启动失败，`tcp_conn_count * mbuf_count_per_conn *` 2048字节不能大于大页大小 |
|mbuf_count_per_conn|170|每个tcp连接需要的mbuf个数，该参数乘以tcp_conn_count是初始化时申请的mbuf地址池大小，配置过小会启动失败，`tcp_conn_count * mbuf_count_per_conn *`2048字节不能大于大页大小|

lstack.conf示例：

```sh  
dpdk_args=["--socket-mem", "2048,0,0,0", "--huge-dir", "/mnt/hugepages-lstack", "--proc-type", "primary", "--legacy-mem", "--map-perfect"]

use_ltran=0
kni_switch=0

low_power_mode=0

num_cpus="2,22"
num_wakeup="3,23"

host_addr="192.168.1.10"
mask_addr="255.255.255.0"
gateway_addr="192.168.1.1"
devices="aa:bb:cc:dd:ee:ff"

send_connect_number=4
read_connect_number=4
rpc_number=4
nic_read_num=128
mbuf_pool_size=1024000
bond_mode=1
bond_slave_mac="aa:bb:cc:dd:ee:ff;AA:BB:CC:DD:EE:FF"
udp_enable=1
nic_vlan_mode=-1
```

- ltran模式功能已衰退，多进程使用需求可尝试使用SR-IOV组网硬件虚拟化组网模式：  

### 7. 启动应用程序

- 启动应用程序  

  启动应用程序前不使用环境变量LSTACK_CONF_PATH指定配置文件，则使用默认路径/etc/gazelle/lstack.conf

  ```sh
  export LSTACK_CONF_PATH=./lstack.conf
  LD_PRELOAD=/usr/lib64/liblstack.so  GAZELLE_BIND_PROCNAME=redis-server redis-server redis.conf
  ```

### 8. API

Gazelle wrap应用程序POSIX接口，应用程序无需修改代码。

### 9. 调测命令

```sh
Usage: gazellectl [-h | help]
  or:  gazellectl lstack {show | set} {ip | pid} [LSTACK_OPTIONS] [time] [-u UNIX_PREFIX]

  where  LSTACK_OPTIONS :=
                  show lstack all statistics
  -r, rate        show lstack statistics per second
  -s, snmp        show lstack snmp
  -c, connetct    show lstack connect
  -l, latency     show lstack latency
  -x, xstats      show lstack xstats
  -k, nic-features show state of protocol offload and other feature
  -a, aggregatin  [time] show lstack send/recv aggregation
  set:
  loglevel        {error | info | debug} set lstack loglevel
  lowpower        {0 | 1} set lowpower enable
  [time]          measure latency time default 1S
```

-u参数指定gazelle进程间通信的unix socket前缀，和需要通信的lstack.conf的unix_prefix配置一致。

**抓包工具**  
gazelle使用的网卡由dpdk接管，因此普通的tcpdump无法抓到gazelle的数据包。作为替代，gazelle使用dpdk-tools软件包中提供的gazelle-pdump作为数据包捕获工具，它使用dpdk的多进程模式和lstack进程共享内存。
[详细使用方法](https://gitee.com/openeuler/gazelle/blob/master/doc/pdump.md)

**线程名绑定**  
lstack启动时可以通过指定环境变量GAZELLE_THREAD_NAME来指定lstack绑定的线程名，在业务进程中有多个不同线程时，可以通过使用此参数来指定需要lstack接管网络接口的线程名，未指定的线程将走内核态协议栈。默认为空，即绑定进程内的所有线程。

### 10. 使用注意

#### 1. dpdk配置文件的位置

如果是root用户，dpdk启动后的配置文件将会放到/var/run/dpdk目录下;
如果是非root用户，dpdk配置文件的路径将由环境变量XDG_RUNTIME_DIR决定；

- 如果XDG_RUNTIME_DIR为空，dpdk配置文件放到/tmp/dpdk目录下；
- 如果XDG_RUNTIME_DIR不为空，dpdk配置文件放到变量XDG_RUNTIME_DIR下；
- 注意有些机器会默认设置XDG_RUNTIME_DIR

## 约束限制

使用 Gazelle 存在一些约束限制：

### 功能约束

- 不支持accept阻塞模式或者connect阻塞模式。
- 最多支持1500个TCP连接。
- 当前仅支持TCP、ICMP、ARP、IPv4、UDP 协议。
- 在对端ping Gazelle时，要求指定报文长度小于等于14000B。
- 不支持使用透明大页。
- 虚拟机网卡不支持多队列。  

### 操作约束

- 提供的命令行、配置文件默认root权限。非root用户使用，需先提权以及修改文件所有者。
- 将用户态网卡绑回到内核驱动，必须先退出Gazelle。
- 大页内存不支持在挂载点里创建子目录重新挂载。
- 每个应用实例协议栈线程最低大页内存为800MB 。
- 仅支持64位系统。
- 构建x86版本的Gazelle使用了-march=native选项，基于构建环境的CPU（Intel® Xeon® Gold 5118 CPU @ 2.30GHz指令集进行优化。要求运行环境CPU支持 SSE4.2、AVX、AVX2、AVX-512 指令集。
- 最大IP分片数为10（ping 最大包长14790B），TCP协议不使用IP分片。
- sysctl配置网卡rp_filter参数为1，否则可能不按预期使用Gazelle协议栈，而是依然使用内核协议栈。
- 不支持使用多种类型的网卡混合组bond。
- bond1主备模式，只支持链路层故障主备切换（例如网线断开），不支持物理层故障主备切换（例如网卡下电、拔网卡）。
- 发送udp报文包长超过45952(32 * 1436)B时，需要将send_ring_size扩大为至少64个。

## 注意事项

用户根据使用场景评估使用Gazelle

ltran模式及kni模块由于上游社区及依赖包变更,功能在新版本中不再支持.

共享内存

- 现状  
  大页内存 mount 至 /mnt/hugepages-lstack 目录，进程初始化时在 /mnt/hugepages-lstack 目录下创建文件，每个文件对应一个大页，并 mmap 这些文件。
- 当前消减措施  
  大页文件权限 600，只有 OWNER 用户才能访问文件，默认 root 用户，支持配置成其他用户；
  大页文件有 DPDK 文件锁，不能直接写或者映射。
- 注意  
  属于同一用户的恶意进程模仿DPDK实现逻辑，通过大页文件共享大页内存，写破坏大页内存，导致Gazelle程序crash。建议用户下的进程属于同一信任域。

**流量限制**  
Gazelle没有做流量限制，用户有能力发送最大网卡线速流量的报文到网络，可能导致网络流量拥塞。

**进程仿冒**  
建议lstack进程都为可信任进程。
