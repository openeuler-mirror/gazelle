# Redis over Gazelle

## Background

  Gazelle is a high-performance user-mode protocol stack. It directly reads and writes NIC packets in user mode based on DPDK, transmits packets by sharing huge page memory, and uses the lightweight LwIP protocol stack. The network I/O throughput of applications is greatly improved.  Focuses on database network performance acceleration, such as MySQL and Redis.

- Redis Performance Test (Kernel vs Gazelle)`<br>`

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

## Function Constraints

- Only IPv4 addresses are supported.
- The maximum number of concurrent users is 20,000.
- One Gazelle cannot accelerate multiple Redis servers.

## Test Procedure

### 1. Requirements

#### 1.1 Hardware

Standalone test: One server and one client are required.`<br>`
Primary/Secondary test: at least two servers (one master server and one slave server) and one client.`<br>`
Sentinel mode: at least two Redis servers (one master and one slave), two sentinel servers, and one client.`<br>`
Cluster mode: At least six Redis servers (three master servers and three slave servers) and one client are deployed.`<br>`

#### 1.2 Software

[Redis software package](https://download.redis.io/releases/). The version used in the test is Redis 6.2.9.

### 2. Deployment on the Server

- Prepare

```sh
# Disable the firewall.
systemctl stop iptables
systemctl stop firewalld
```

#### 2.1 Compiling and Installing Redis

- Compiling Redis(Optional)

```sh
tar zxvf redis-6.2.9.tar.gz 
cd redis-6.2.9/
make clean
make -j 32
make install
```

#### 2.2 Deploying Gazelle

- RPM Install

```sh
yum -y install gazelle dpdk libconfig numactl libboundscheck libcap 
```

- Modify the following parameters in the /etc/gazelle/lstack.conf file. Retain the default values for other parameters.

| Configuration Item  | Value                                                                                           | Description                                                                                                                                                                                                                                                                                                    |
| ------------------- | ----------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| dpdk_args           | ["--socket-mem", "2400,0,0,0", "--huge-dir", "/mnt/hugepages-lstack", "--proc-type", "primary"] | Configure the NUMA where the CPU and NIC are located to use 2400 MB memory (which can be reduced based on the number of concurrent tasks). If the CPU and NIC are not in the same NUMA, the memory must be configured for the NUMA. If the MLX NIC is used, the "-d", "librte_net_mlx5.so" must be configured. |
| num_cpus            | "2"                                                                                             | Select a CPU and bind it to the lstack.                                                                                                                                                                                                                                                                        |
| mbuf_count_per_conn | 34                                                                                              | Number of mbufs required by each connection                                                                                                                                                                                                                                                                    |
| tcp_conn_count      | 20000                                                                                           | Maximum number of concurrent Redis tests                                                                                                                                                                                                                                                                       |

```sh
# Allocate huge pages
mkdir -p /mnt/hugepages-lstack
chmod -R 700 /mnt/hugepages-lstack
mount -t hugetlbfs nodev /mnt/hugepages-lstack -o pagesize=2M # The operation cannot be performed repeatedly. Otherwise, the huge page is occupied and cannot be released.
echo 2048 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages # Select a page size based on the site requirements.
cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages # Queries the available hugepage memory on the corresponding node.

# Load the ko file. (Skip this step if the NIC is an mlx NIC.)
modprobe vfio enable_unsafe_noiommu_mode=1
modprobe vfio-pci

# Bind the network adapter to the user mode. (Skip this step for the mlx network adapter.)
ip link set enp4s0 down
dpdk-devbind -b vfio-pci enp4s0

# Gazelle has been deployed and the app is to be deployed.
```

- For details about how to deploy Gazelle, see [Gazelle User Guide](./user-guide_en.md)
- For details about how to bind different network adapters in user mode, see [Gazelle Network Adapter Support and Usage](./nic-support_en.md)

#### 2.3 Redis Server Deployment

- In all scenarios, the redis.conf file of the Redis server needs to be configured as follows:

```sh
# Disable Protection Mode
protected-mode no
# Gazelle does not support this parameter for background running.
daemonize no
# Configure AOF persistency. This parameter is optional in the Redis single-node system test.
appendonly yes
```

##### 2.3.1 Redis single-node system deployment

The Redis single-node system test contains a server. After the Gazelle and Redis are deployed, the Gazelle+Redis service can be directly started.

```sh
LD_PRELOAD=/usr/lib64/liblstack.so GAZELLE_BIND_PROCNAME=redis-server redis-server /root/redis-6.2.9/redis.conf
```

##### 2.3.2 redis primary/secondary mode deployment

primary/secondary replication indicates that data on a Redis server is replicated to other Redis servers. The former is called the master node, and the latter is called the slave node. Data replication is unidirectional and data can only be transmitted from the master node to the slave node. The redis primary/secondary mode contains at least two servers. The configuration methods are as follows:

- mode1`<br>`
  Add the following configuration to the redis.conf configuration file on the node and start the redis primary/secondary node:

```sh
# 192.168.1.127 6379 is the IP address and port number of the primary node.
slaveof 192.168.1.127 6379
```

```sh
LD_PRELOAD=/usr/lib64/liblstack.so GAZELLE_BIND_PROCNAME=redis-server redis-server /root/redis-6.2.9/redis.conf
```

- mode2`<br>`
  After the general configuration of the primary/secondary node is modified, start the Redis primary/secondary node. (At this time, the primary/secondary relationship has not been established.) Run the following command on the client:

```sh
redis-cli -h 192.168.1.127 slaveof NO ONE # primary node
redis-cli -h 192.168.1.128 slaveof 192.168.1.127 6379 # slave node
```

- primary/secondary information query`<br>`

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

##### 2.3.3 Redis deployment in Sentinel mode

The sentinel mode is based on the primary/secondary replication mode, however, sentries are introduced to monitor and automatically process faults. The primary/secondary switchover technology is as follows: When a server breaks down, you need to manually switch a slave server to the master server, which is time-consuming and requires manual intervention. In addition, services are unavailable for a period of time.
To solve the defect of the primary/secondary replication, the sentinel mechanism is used. The Redis sentinel mode test requires at least two Redis servers and two sentinel servers.

- Start the two Redis servers in primary/secondary mode. `<br>`
- Install and deploy the Redis on two sentinel servers and modify the sentinel.conf file.

```sh
protected-mode no # Disable Protection Mode
daemonize yes # Background running. Logs are recorded in logfile.
logfile "/var/log/sentinel.log" # Specifying the path for storing logs
sentinel monitor mymaster 192.168.1.127 6379 1 # The name of the master node is mymaster, which monitors the IP address and port number of the master node. At least one sentinel node is required to determine that the master node is faulty and perform failover.
sentinel down-after-milliseconds mymaster 30000 # Interval for determining whether a server port is down. The default value is 30000 ms (30 seconds). Other ports are not supported.
sentinel failover-timeout mymaster 50000 # The maximum timeout interval of a faulty node is 50000.
```

- Start the sentry (in kernel mode) and query the sentry information.

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

Notes：`<br>`
a. The Redis server and Redis sentinel cannot be on the same node. Otherwise, the switchover between the active and standby Redis servers cannot be performed.`<br>`
b. Redis Sentinel does not support user-mode startup.

##### 2.3.4 Redis cluster deployment

The concurrent capability of the Redis on a single node is limited. To further improve the concurrent capability of the Redis, you need to set up a primary/secondary cluster, it provides an assembly for sharing data among multiple Redis nodes. The Redis cluster test requires at least six Redis servers.

- Install Redis on the six Redis servers and modify the redis.conf configuration file.

```sh
protected-mode no # Disable Protection Mode
daemonize yes # Foreground running
bind 0.0.0.0
port 6379 # Redis is deployed on different VMs with different IP addresses. You can retain the default port number.
appendonly yes # Enabling AOF Persistence
cluster-enabled yes # Enable the cluster mode.
cluster-config-file nodes.conf # Name of the configuration file in cluster mode, which is automatically maintained by the cluster and does not need to be manually created.
cluster-node-timeout 5000 # Timeout interval of heartbeats between nodes in a cluster.
```

- Start six Redis servers`<br>`

```sh
LD_PRELOAD=/usr/lib64/liblstack.so GAZELLE_BIND_PROCNAME=redis-server redis-server /root/redis-6.2.9/redis.conf
```

- On the client, run the following command to create a cluster and approve the allocation of master and slave nodes in the cluster:

```sh
[root@openEuler redis-6.2.9]# redis-cli --cluster create --cluster-replicas 1 192.168.1.127:6379 192.168.1.128:6379 192.168.1.129:6379 192.168.1.130:6379 192.168.1.131:6379 192.168.1.132:6379
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
[OK] All 16384 slots covered. # hash slotsIf all slots are allocated, the cluster is created successfully.

# redis-cli --cluster: indicates the cluster operation command. create: indicates to create a cluster. --cluster-replicas 1: indicates that the number of replicas of each master node in the cluster is 1.
#Total number of nodes/(replicas + 1) = Number of master nodes. Therefore, the first n nodes in the node list are master nodes. Other nodes are slave nodes and are randomly allocated to different master nodes.
```

- Querying Cluster Information`<br>`
  Any server that is running properly in the cluster can be used as a breakthrough point.

```sh
# Viewing Cluster Status Information
[root@openEuler redis-6.2.9]# redis-cli -h 192.168.1.127 cluster info
cluster_state:ok # If the status is fail, check whether hash slots fail to be allocated.
cluster_slots_assigned:16384
cluster_slots_ok:16384
cluster_slots_pfail:0
cluster_slots_fail:0
......
```

```sh
# Check the primary/secondary relationship of the cluster.
[root@openEuler redis-6.2.9]# redis-cli -h 192.168.1.128 cluster nodes
514b35aaa5035d489b60a0e8f8fb01d1c20734ce 192.168.1.129:6379@16379 slave 50aa44a1e4a6a0c75cf2f9b20055bfaa77d1b163 0 1724919619916 1 connected
50aa44a1e4a6a0c75cf2f9b20055bfaa77d1b163 192.168.1.127:6379@16379 master - 0 1724919617960 1 connected 0-5460
a94402ca747ead08e4b93ff975dfbe995068ecbf 192.168.1.130:6379@16379 slave 0a569e1ac4e373a22abcbf6ce6b8118fba3d4d6e 0 1724919618000 3 connected
8c4040a4fa8456044acad2518dc45b8236ba44c4 192.168.1.128:6379@16379 myself,slave 44a96161651c8383fb4966c6dde45d400fe2a203 0 1724919617000 2 connected
0a569e1ac4e373a22abcbf6ce6b8118fba3d4d6e 192.168.1.132:6379@16379 master - 0 1724919618975 3 connected 10923-16383
44a96161651c8383fb4966c6dde45d400fe2a203 192.168.1.131:6379@16379 master - 0 1724919619617 2 connected 5461-10922
# Nodes 127, 131, and 132 are master nodes, and nodes 128, 129, and 130 are slave nodes. You can find the corresponding master nodes based on the node IDs of the slave nodes.
```

### 3. Deploying the redis-benchmark Tool on the Client

- Compilation & Installation

redis-benchmark is a built-in test tool of the Redis. You only need to compile and install the Redis in the same way as the server.

- Test

```sh
# Single server, primary/secondary mode, Sentinel mode
# set,get
redis-benchmark -h 192.168.1.127 -p 6379 -c 1000 -n 10000000 -d 3 -r 10000000 -t set,get --threads 12
#-h: specifies the Redis server address. -p: specifies the Redis server port. -c: specifies the number of concurrent connections on the client. -n: specifies the total number of requests. -t: specifies the test command. -d: specifies the data packet size.
# In <S0> <M0> <S1> primary/secondary <S2> and sentinel modes, the slave-read-only yes command is configured by default. Therefore, only the get command can be executed on the Redis database of the slave node.
```

```sh
# Cluster Mode
#set,get
redis-benchmark -h 192.168.1.127 -p 6379 -c 1000 -n 10000000 -d 3 -r 10000000 -t set,get --threads 12 --cluster
# -h: Specify any available node in the cluster.
```
