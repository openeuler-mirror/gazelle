<img src="doc/logo.png" alt="gazelle" style="zoom:20%;" />  

# gazelle

## Introduction
gazelle是高性能的用户态协议栈，通过dpdk在用户态直接读写网卡报文，共享大页内存传递报文，并使用轻量级lwip协议栈。能够大幅提高应用的网络IO吞吐能力.

## Compile
- 编译依赖软件包  
cmake gcc-c++ lwip dpdk-devel(>=19.11-0.h12)
numactl-devel libpcap-devel libconfig-devel rpm-build
- 编译
``` sh
#创建目录
mkdir -p ~/rpmbuild/SPECS
mkdir -p ~/rpmbuild/SOURCES

#创建压缩包
mkdir gazelle-1.0.0
mv build gazelle-1.0.0
mv src gazelle-1.0.0
tar zcvf gazelle-1.0.0.tar.gz gazelle-1.0.0/

#编包
mv gazelle-1.0.0.tar.gz ~/rpmbuild/SPECS
cp gazelle.spec ~/rpmbuild/SPECS
cd ~/rpmbuild/SPECS
rpmbuild -bb gazelle.spec

#编出的包
ls ~/rpmbuild/RPMS
```

## Install
``` sh 
#dpdk >= 19.11-0.h12
yum install dpdk
yum install libconfig
yum install numact
yum install libpcap
yum install gazelle
```

## Use
### 1. 安装igb_uio.ko
``` sh
modprobe uio
insmod /lib/modules/4.19.90-vhulk2007.2.0.h188.eulerosv2r9.aarch64/extra/dpdk/igb_uio.ko
```

### 2. dpdk绑定网卡
- 对于虚拟网卡或一般物理网卡，绑定到驱动igb_uio
``` sh
dpdk-devbind -b igb_uio enp3s0
```
- 1822网卡绑定到驱动vfio-pci（由kernel提供）
``` sh
modprobe vfio-pci
dpdk-devbind -b vfio-pci enp3s0 
```

### 3. 大页内存配置  
dpdk提供了高效的大页内存管理和共享机制，gazelle的报文数据、无锁队列等都使用了大页内存。大页内存需要root用户配置。2M或1G大页按实际需要配置，推荐使用2M大页内存，该内存是本机上ltran和所有lstack可以使用的总内存，具体方法如下：
- 2M大页配置  
  - 配置系统大页数量
    ``` sh
    #示例：在node0上配置2M * 2000 = 4000M
    echo 2000 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
    echo 0 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages
    echo 0 > /sys/devices/system/node/node2/hugepages/hugepages-2048kB/nr_hugepages
    echo 0 > /sys/devices/system/node/node3/hugepages/hugepages-2048kB/nr_hugepages
    # 查看配置结果
    grep Huge /proc/meminfo
    ```
- 1G大页配置  
1G大页配置方法与2M类似
  - 配置系统大页数量
    ``` sh
    #示例：在node0上配置1G * 5 = 5G
    echo 5 > /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages
    ```

### 4. 挂载大页内存  
创建两个目录，分别给lstack的进程、ltran进程使用。操作步骤如下：  
``` sh
mkdir -p /mnt/hugepages
mkdir -p /mnt/hugepages-2M
chmod -R 700 /mnt/hugepages
chmod -R 700 /mnt/hugepages-2M
mount -t hugetlbfs nodev /mnt/hugepages
mount -t hugetlbfs nodev /mnt/hugepages-2M
```

### 5. 重新编译应用，使其从内核协议栈切换至用户态协议栈  
修改应用的makefile文件，使其链接liblstack.so。示例如下：
``` makefile
#在makefile中添加
ifdef USE_GAZELLE
    -include /etc/gazelle/lstack.Makefile
endif
gcc test.c -o test $(LSTACK_LIBS)
```

### 6. 配置文件  
- ltran.conf用于指定ltran启动的参数，Gazelle发布件会包括ltran.conf供用户参考，路径为/etc/gazelle/ltran.conf，配置文件格式如下  

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
<style> table th:nth-of-type(3) { width: 130px; } </style>  
ltran.conf示例：
``` conf
forward_kit="dpdk"
forward_kit_args="-l 0,1 --socket-mem 1024,0,0,0 --huge-dir /mnt/hugepages --proc-type primary --legacy-mem --map-perfect"

kni_switch=0

dispatch_subnet="192.168.1.0"
dispatch_subnet_length=8
dispatch_max_clients=30

bond_mode=1
bond_miimon=100
bond_mtu=1500
bond_ports="0x1"
bond_macs="30:fd:65:e3:39:63"
```  

- lstack.conf用于指定lstack的启动参数，配置文件参数如下  

|选项|参数格式|说明|
|:---|:---|:---|
|dpdk_args|-l<br>--socket-mem（必需）<br>--huge-dir（必需）<br>--proc-type（必需）<br>等|dpdk初始化参数，参考dpdk说明|
|num_cpus|n|共享队列数量，该值目前不生效，默认为1<br>保留字段，目前未使用|
|host_addr|"192.168.xx.xx"|协议栈的IP地址，必须和redis-server配置<br>文件里的“bind”字段保存一致。|
|mask_addr|"255.255.xx.xx"|掩码地址|
|gateway_addr|"192.168.xx.1"|网关地址|
|devices|"aa:bb:cc:dd:ee:ff"|网卡通信的mac地址，需要与ltran.conf的bond_macs配置一致|
<style> table th:nth-of-type(1) { width: 130px; } </style>
<style> table th:nth-of-type(2) { width: 130px; } </style>

lstack.conf示例：
``` conf
dpdk_args=["-l", "2", "--socket-mem", "2048,0,0,0","--huge-dir", "/mnt/hugepages-2M", "--proc-type", "primary"]
num_cpus=1

host_addr="192.168.1.10"
mask_addr="255.255.255.0"
gateway_addr="192.168.1.1"
devices="30:fd:65:e3:39:63"
```
### 7. 启动  
- 启动ltran，如果不指定--config-file，则使用默认路径/etc/gazelle/ltran.conf
``` sh
ltran --config-file ./ltran.conf
```
- 启动redis，如果不指定环境变量LSTACK_CONF_PATH，则使用默认路径/etc/gazelle/lstack.conf
``` sh
export LSTACK_CONF_PATH=./lstack.conf
redis-server redis.conf
```

### 8. API
liblstack.so编译进应用程序后wrap网络编程标准接口，应用程序无需修改代码，但是应用程序必须使用epoll机制。

### 9. gazellectl
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
+ 如果XDG_RUNTIME_DIR为空，dpdk配置文件放到/tmp/dpdk目录下；
+ 如果XDG_RUNTIME_DIR不为空，dpdk配置文件放到变量XDG_RUNTIME_DIR下；
+ 注意有些机器会默认设置XDG_RUNTIME_DIR

## Constraints
- Gazelle提供的命令行及配置文件仅root权限开源执行或修改。配置大页内存需要
root用户执行操作。
- 在将网卡绑定到igb_uio后（详见3），禁止将网卡绑回ixgbe。
- 如果需要把Gazelle使用的网卡绑回ixgbe驱动，或者从igb_uio驱动解绑，不允许
在Gazelle还在运行时执行上述操作，须先将Gazelle退出，再将执行unbind或者
bind操作，否则会导致内核panic。
- Gazelle不支持accept阻塞模式或者connect阻塞模式。
- Gazelle最多只支持20000个链接（需要保证进程内，非网络连接的fd个数小于
2000个）。支持20000个连接只作为功能完备性考虑。当流量较大时，可能会出
现部分丢包。
- Gazelle协议栈当前只支持tcp、icmp、arp、ipv4，使用其他协议可能导致实例异
常。
- Gazelle不允许在一个挂载点里面创建子目录重新挂载，否则可能对大页挂载路径
重复初始化，导致应用启动失败。
- Gazelle组件自身无数据安全风险，但是依赖dpdk的共享内存管理。如果dpdk的
大页内存管理机制存在安全问题，Gazelle中的共享内存有被攻击的风险。
- 在对端使用ping命令时，要求指定报文长度小于等于14000。报文长度超过14000
时行为不可预测。
- Gazelle不支持使用透明大页。
- 需要保证ltran的可用大页内存 >=850M。
- 需要保证lstack实例一个网络线程的可用大页内存 >=500M。
- Gazelle不支持32位系统使用。
- ltran不支持使用多种类型的网卡混合组bond。
- ltran的bond1主备模式，只支持链路层故障主备切换（例如网线断开），不支持
物理层故障主备切换（例如网卡下电、拔网卡）。
- 构建X86版本使用-march=native选项，基于构建环境的CPU（Intel® Xeon® Gold
5118 CPU @ 2.30GHz）指令集进行优化。要求运行环境CPU支持SSE4.2、AVX、
AVX2、AVX-512指令集。
- Gazelle的最大IP分片数为10（ping最大包长14790），TCP协议不使用IP分片。
- 使用sysctl配置rp_filter参数为1，否则可能连接使用内核协议栈

## Security risk note
gazelle有如下安全风险，用户需要评估使用场景风险  
1. 共享内存  
- 现状  
大页内存mount至/mnt/hugepages-2M目录，链接liblstack.so的进程初始化时在/mnt/hugepages-2M目录下创建文件，每个文件对应2M大页内存，并mmap这些文件。ltran在收到lstask的注册信息后，根据大页内存配置信息也mmap目录下文件，实现大页内存共享。
ltran在/mnt/hugepages目录的大页内存同理。
- 当前消减措施  
大页文件权限600，只有OWNER用户才能访问文件，默认root用户，支持配置成其它用户；  
大页文件有dpdk文件锁，不能直接写或者mmap。
- 风险点  
属于同一用户的恶意进程模仿DPDK实现逻辑，通过大页文件共享大页内存，写破坏大页内存，导致gazelle程序crash。建议用户下的进程属于同一信任域。
2. 流量限制  
- 风险点  
gazelle没有做流量限制，用户有能力发送最大网卡线速流量的报文到网络。
3. 进程仿冒  
- 风险点  
合法注册到ltran的两个lstack进程，进程A可仿冒进程B发送仿冒消息给ltran，修改ltran的转发控制信息，造成进程B通讯异常，进程B报文转发给进程A等问题。建议lstack进程都为可信任进程。

## How to Contribute
We are happy to provide guidance for the new contributors.  
Please sign the CLA before contributing.

## Licensing
gazelle is licensed under the Mulan PSL v2.


