# Gazelle加速redis

## 背景介绍
  Gazelle是一款高性能用户态协议栈。它基于DPDK在用户态直接读写网卡报文，共享大页内存传递报文，使用轻量级LwIP协议栈。能够大幅提高应用的网络I/O吞吐能力。专注于数据库网络性能加速，如MySQL、redis等。

- Gazelle相比于内核协议栈在redis测试中有明显的提升<br>
以8u32g规格arm虚拟机的set和get测试结果为例，其中连接数为1k，包长为默认包长3。
```sh
#kernel
redis-benchmark -h 192.168.1.127 -p 6379 -c 1000 -n 10000000 -r 10000000 -t set,get --threads 12
#set
Summary:
  throughput summary: 132402.98 requests per second
  latency summary (msec):
          avg       min       p50       p95       p99       max
        7.474     1.376     7.207     9.399    14.255    30.879
#get
Summary:
  throughput summary: 142834.69 requests per second
  latency summary (msec):
          avg       min       p50       p95       p99       max
        6.919     1.384     6.663     8.751    13.311    24.207
```
```sh
#gazelle
redis-benchmark -h 192.168.1.127 -p 6379 -c 1000 -n 10000000 -r 10000000 -t set,get --threads 12
#set
Summary:
  throughput summary: 359389.03 requests per second
  latency summary (msec):
          avg       min       p50       p95       p99       max
        2.736     0.240     2.735     2.895     3.127     9.471
#get
Summary:
  throughput summary: 359401.97 requests per second
  latency summary (msec):
          avg       min       p50       p95       p99       max
        2.752     0.488     2.751     2.903     3.135    16.671
```

## 功能约束
- 当前仅支持IPV4，IPV6暂不支持
- 并发数限制最大为2w
- 当前不支持gazelle多进程，即一个节点上不能用gazelle启动多个redis server

## Gazelle加速redis测试步骤

### 1. 环境要求

#### 1.1 硬件

单机测试需要服务端（Server）、客户端（Client）各一台；<br>
主从模式测试至少两台服务端（一主一从）、一台客户端；<br>
哨兵模式测试至少两台redis服务端（一主一从）、两台哨兵服务端、一台客户端；<br>
集群模式测试至少六台redis服务端（三主三从）、一台客户端。<br>

#### 1.2 软件

[redis软件包下载](https://download.redis.io/releases/)，当前测试使用版本为redis-6.2.9。

### 2. Server端部署

- 关闭测试影响项
```sh
#关闭防火墙
systemctl stop iptables
systemctl stop firewalld
```

#### 2.1 编译安装redis

- 编译redis

```sh
tar zxvf redis-6.2.9.tar.gz 
cd redis-6.2.9/
make clean
make -j 32
make install
```

#### 2.2 gazelle运行环境部署

- 安装gazelle及依赖

```sh
yum -y install gazelle dpdk libconfig numactl libboundscheck libcap 
```

- 修改/etc/gazelle/lstack.conf配置文件中参数如下，其他配置参数可保持默认值。

| 配置项        | 值                                                           | 描述                                                         |
| ------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| dpdk_args     | ["--socket-mem", "2400,0,0,0", "--huge-dir", "/mnt/hugepages-lstack", "--proc-type", "primary"] | 配置cpu和网卡所在的numa使用2400M内存（可根据并发数减少）；如果cpu和网卡不在一个numa上，则对应numa都需要配置内存；如果是mlx网卡，需要追加配置"-d", "librte_net_mlx5.so" |
| num_cpus      | "2"                                                          | 选择一个cpu绑定lstack                                         |
| mbuf_count_per_conn| 34                                                       | 每个连接需要的mbuf数量                                        |
| tcp_conn_count     | 20000                                                         | redis测试最大并发数                                         |

```sh
#服务端分配大页
mkdir -p /mnt/hugepages-lstack
chmod -R 700 /mnt/hugepages-lstack
mount -t hugetlbfs nodev /mnt/hugepages-lstack -o pagesize=2M #不能重复操作，否则大页被占用不能释放
echo 2048 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages #根据实际选择pagesize
cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages #查询对应node上实际可用的大页内存

#服务端加载ko（mlx网卡可跳过此步骤）
modprobe vfio enable_unsafe_noiommu_mode=1
modprobe vfio-pci

#服务端绑定网卡到用户态（mlx网卡可跳过此步骤）
ip link set enp4s0 down
dpdk-devbind -b vfio-pci enp4s0

#gazelle部署完成，待app部署
```
- Gazelle部署详见[Gazelle用户指南](https://gitee.com/openeuler/gazelle/blob/master/doc/user-guide.md)<br>
- 不同网卡绑定用户态方法详见[Gazelle网卡支持及使用](https://gitee.com/openeuler/gazelle/blob/master/doc/nic-support.md)

#### 2.3 redis服务端部署

- 所有场景的redis server的redis.conf文件，均需要做如下配置：

```sh
#关闭保护模式
protected-mode no
#gazelle暂不支持此参数进行后台运行
daemonize no
#开启AOF持久化，redis单机测试可不配置
appendonly yes
```

##### 2.3.1 redis单机部署

redis单机测试包含一台server，部署好gazelle和redis后，可以直接启动gazelle+redis服务

```sh
LD_PRELOAD=/usr/lib64/liblstack.so GAZELLE_BIND_PROCNAME=redis-server redis-server /root/redis-6.2.9/redis.conf
```

##### 2.3.2 redis主从模式部署

主从复制，是指将一台Redis服务器的数据，复制到其他的Redis服务器。前者称为主节点(Master)，后者称为从节点(Slave)；数据的复制是单向的，只能由主节点到从节点。redis主从模式包括至少两台server，配置方法有两种：

- 主从配置方式1<br>
从节点redis.conf配置文件中添加如下配置，然后分别启动redis主从节点
```sh
#192.168.1.127 6379为主节点服务的ip和port
slaveof 192.168.1.127 6379
```
```sh
LD_PRELOAD=/usr/lib64/liblstack.so GAZELLE_BIND_PROCNAME=redis-server redis-server /root/redis-6.2.9/redis.conf
```

- 主从配置方式2<br>
完成主从节点通用配置修改后，启动redis主从节点（此时还没有建立主从关系），在客户端执行以下命令
```sh
redis-cli -h 192.168.1.127 slaveof NO ONE #主节点
redis-cli -h 192.168.1.128 slaveof 192.168.1.127 6379 #从节点
```

- 主从信息查询<br>

```sh
[root@openEuler redis-6.2.9]# redis-cli -h 192.168.1.127 info Replication
# Replication
role:master
connected_slaves:1
slave0:ip=192.168.1.128,port=6379,state=online,offset=780,lag=0
......
```
```sh
[root@openEuler redis-6.2.9]# redis-cli -h 192.168.1.128 info Replication
# Replication
role:slave
master_host:192.168.1.127
master_port:6379
master_link_status:up
......
```

##### 2.3.3 redis哨兵模式部署

哨兵模式基于主从复制模式，只是引入了哨兵来监控与自动处理故障。主从切换技术的方法是：当服务器宕机后，需要手动一台从机切换为主机，这需要人工干预，不仅费时费力而且还会造成一段时间内服务不可用。为了解决主从复制的缺点，就有了哨兵机制。redis哨兵模式测试至少需要两台redis服务端和两台哨兵服务端。
- 按照主从模式部署方法将两台redis服务端启动<br>
- 在两台哨兵服务端安装部署redis，分别修改sentinel.conf配置文件
```sh
protected-mode no #关闭保护模式
daemonize yes #后台运行，日志记录在logfile
logfile "/var/log/sentinel.log" #指定日志存放路径
sentinel monitor mymaster 192.168.1.127 6379 1 #该主节点的名称是mymaster，监控master的ip、端口，1是至少需要1个哨兵节点同意，才能判定主节点故障并进行故障转移
sentinel down-after-milliseconds mymaster 30000 #判断服务器down掉的时间周期，默认30000毫秒（30秒）
sentinel failover-timeout mymaster 50000 #故障节点的最大超时时间为50000
```
- 启动哨兵（内核态启动），查询哨兵信息
```sh
[root@openEuler redis-6.2.9]#redis-sentinel sentinel.conf
[root@openEuler redis-6.2.9]#ps -ef|grep redis-sentinel 
root       5961      1  0 13:36 ?        00:00:00 redis-sentinel *:26379 [sentinel]
[root@openEuler redis-6.2.9]#redis-cli -p 26379 info sentinel
# Sentinel
sentinel_masters:1
sentinel_tilt:0
sentinel_running_scripts:0
sentinel_scripts_queue_length:0
sentinel_simulate_failure_flags:0
master0:name=mymaster,status=ok,address=192.168.1.127:6379,slaves=2,sentinels=3
```

注：<br>
a. redis server和redis 哨兵不可以在同一个节点上，否则无法正常主备切换；<br>
b. redis 哨兵暂不支持用户态启动。

##### 2.3.4 redis集群模式部署
单节点Redis的并发能力是有上限的，要进一步提高Redis的并发能力，就需要搭建主从集群，其作用是提供在多个Redis节点间共享数据的程序集。redis集群测试至少需要六台redis服务端。
- 在六台redis服务端安装部署redis，分别修改redis.conf配置文件
```sh
protected-mode no #关闭保护模式
daemonize yes #前台运行
bind 0.0.0.0
port 6379 #redis部署在不同的虚机上，ip不一样，端口可以保持默认
appendonly yes #开启aof持久化
cluster-enabled yes #开启集群模式
cluster-config-file nodes.conf #集群模式的配置文件名称，无需手动创建，由集群自动维护
cluster-node-timeout 5000 #集群中节点之间心跳超时时间
```
- 分别启动六台redis服务端<br>
```sh
LD_PRELOAD=/usr/lib64/liblstack.so GAZELLE_BIND_PROCNAME=redis-server redis-server /root/redis-6.2.9/redis.conf
```

- 在客户端执行命令创建集群，同意集群中master与slave节点的分配情况
```sh
[root@openEuler redis-6.2.9]#redis-cli --cluster create --cluster-replicas 1 192.168.1.127:6379 192.168.1.128:6379 192.168.1.129:6379 192.168.1.130:6379 192.168.1.131:6379 192.168.1.132:6379
>>> Performing hash slots allocation on 6 nodes...
......
Can I set the above configuration? (type 'yes' to accept): yes
>>> Nodes configuration updated
>>> Assign a different config epoch to each node
>>> Sending CLUSTER MEET messages to join the cluster
Waiting for the cluster to join
...
>>> Performing Cluster Check (using node 192.168.1.127:6379)
......
[OK] All nodes agree about slots configuration.
>>> Check for open slots...
>>> Check slots coverage...
[OK] All 16384 slots covered. #hash slots分配OK则集群创建成功

#redis-cli --cluster：代表集群操作命令；create：代表是创建集群；--cluster-replicas 1 ：指定集群中每个master的副本个数为1
#此时节点总数 ÷ (replicas + 1) 得到的就是master的数量n。因此节点列表中的前n个节点就是master，其它节点都是slave节点，随机分配到不同master
```
- 查询集群信息<br>
集群中任意一个正常运行的server都可以作为切入点
```sh
#查看集群状态信息
[root@openEuler redis-6.2.9]# redis-cli -h 192.168.1.127 cluster info
cluster_state:ok #如果这里是fail，可以看下hash slots分配失败
cluster_slots_assigned:16384
cluster_slots_ok:16384
cluster_slots_pfail:0
cluster_slots_fail:0
......
```
```sh
#查看集群的主从关系
[root@openEuler redis-6.2.9]# redis-cli -h 192.168.1.128 cluster nodes
514b35aaa5035d489b60a0e8f8fb01d1c20734ce 192.168.1.129:6379@16379 slave 50aa44a1e4a6a0c75cf2f9b20055bfaa77d1b163 0 1724919619916 1 connected
50aa44a1e4a6a0c75cf2f9b20055bfaa77d1b163 192.168.1.127:6379@16379 master - 0 1724919617960 1 connected 0-5460
a94402ca747ead08e4b93ff975dfbe995068ecbf 192.168.1.130:6379@16379 slave 0a569e1ac4e373a22abcbf6ce6b8118fba3d4d6e 0 1724919618000 3 connected
8c4040a4fa8456044acad2518dc45b8236ba44c4 192.168.1.128:6379@16379 myself,slave 44a96161651c8383fb4966c6dde45d400fe2a203 0 1724919617000 2 connected
0a569e1ac4e373a22abcbf6ce6b8118fba3d4d6e 192.168.1.132:6379@16379 master - 0 1724919618975 3 connected 10923-16383
44a96161651c8383fb4966c6dde45d400fe2a203 192.168.1.131:6379@16379 master - 0 1724919619617 2 connected 5461-10922
#可以看出127、131、132是master节点，128、129、130为slave节点，且可以通过slave后的node id找到其对应的master节点
```

### 3. client部署redis-benchmark工具

- 编译安装

redis-benchmark为redis自带的测试工具，与服务端一样编译安装redis即可。

- 测试命令
```sh
#单机、主从模式、哨兵模式
#set,get
redis-benchmark -h 192.168.1.127 -p 6379 -c 1000 -n 10000000 -d 3 -r 10000000 -t set,get --threads 12
#其中，-h：指定redis服务端地址；-p：指定redis服务端端口；-c：指定客户端并发连接数；-n：指定请求总数；-t：指定测试命令；-d：指定数据包大小
#主从模式和哨兵模式下，由于默认配置了slave-read-only yes，从节点redis只能执行get命令。
```
```sh
#集群模式
#set,get
redis-benchmark -h 192.168.1.127 -p 6379 -c 1000 -n 10000000 -d 3 -r 10000000 -t set,get --threads 12 --cluster
#-h只需指定集群中任意一个可用节点即可
```
