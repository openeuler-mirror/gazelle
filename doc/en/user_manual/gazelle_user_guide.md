# Gazelle User Guide

## Overview

Gazelle is a high-performance user-mode protocol stack. It directly reads and writes NIC packets in user mode based on DPDK and transmit the packets through shared hugepage memory, and uses the LwIP protocol stack. Gazelle greatly improves the network I/O throughput of applications and accelerates the network for the databases, such as MySQL and Redis.

- High Performance
    Zero-copy and lock-free packets that can be flexibly scaled out and scheduled adaptively.
- Universality
    Compatible with POSIX without modification, and applicable to different types of applications.

In the single-process scenario where the NIC supports multiple queues, use **liblstack.so** only to shorten the packet path.

## Installation

Configure the Yum source of openEuler and run the`yum` command to install Gazelle.

```sh
yum install dpdk
yum install libconfig
yum install numactl
yum install libboundscheck
yum install libpcap
yum install gazelle
```

> NOTE:  
> The version of dpdk must be 21.11-2 or later.

## How to Use

To configure the operating environment and use Gazelle to accelerate applications, perform the following steps:

### 1. Installing the .ko File as the root User

Install the .ko files based on the site requirements to bind NICs to the user-mode driver.

Bind the NIC from the kernel driver to the user-mode driver. Choose one of the following .ko files based on the site requirements.

```sh
#If the IOMMU is available
modprobe vfio-pci

#If the IOMMU is not available and the VFIO supports the no-IOMMU mode
modprobe vfio enable_unsafe_noiommu_mode=1
modprobe vfio-pci

#Other cases
modprobe igb_uio
```

>NOTE:
You can check whether the IOMMU is enabled based on the BIOS configuration.

### 2. Binding the NIC Using DPDK

Bind the NIC to the driver selected in Step 1 to provide an interface for the user-mode NIC driver to access the NIC resources.

```sh
#Using vfio-pci
dpdk-devbind -b vfio-pci enp3s0 

#Using igb_uio
dpdk-devbind -b igb_uio enp3s0
```

### 3. Configuring Memory Huge Pages

Gazelle uses hugepage memory to improve efficiency. You can configure any size for the memory huge pages reserved by the system using the **root** permissions. Each memory huge page requires a file descriptor. If the memory is large, you are advised to use 1 GB huge pages to avoid occupying too many file descriptors.
Select a page size based on the site requirements and configure sufficient memory huge pages. Run the following commands to configure huge pages:

```sh
#Configuring 1024 2 MB huge pages on node0. The total memory is 2 GB.
echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages

#Configuring 5 1 GB huge pages on node0. The total memory is 5 GB.
echo 5 > /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages
```

>NOTE:
Run the **cat** command to query the actual number of reserved pages. If the continuous memory is insufficient, the number may be less than expected.

### 4. Mounting Memory Huge Pages

Create a directory for the lstack process to access the memory huge pages. Run the following commands:

```sh
mkdir -p /mnt/hugepages-lstack
chmod -R 700 /mnt/hugepages-lstack

mount -t hugetlbfs nodev /mnt/hugepages-lstack -o pagesize=2M
```

### 5. Enabling Gazelle for an Application

Enable Gazelle for an application using either of the following methods as required.

- Recompile the application and replace the sockets interface.

```sh
#Add the Makefile of Gazelle to the application makefile.
-include /etc/gazelle/lstack.Makefile

#Add the LSTACK_LIBS variable when compiling the source code.
gcc test.c -o test ${LSTACK_LIBS}
```

- Use the **LD_PRELOAD** environment variable to load the Gazelle library.
    Use the **GAZELLE_BIND_PROCNAME** environment variable to specify the process name, and **LD_PRELOAD** to specify the Gazelle library path.

    ```sh
    GAZELLE_BIND_PROCNAME=test LD_PRELOAD=/usr/lib64/liblstack.so ./test
    ```

- Use the **GAZELLE_THREAD_NAME** environment variable to specify the thread bound to Gazelle.
    If only one thread of a multi-thread process meets the conditions for using Gazelle, use **GAZELLE_THREAD_NAME** to specify the thread for using Gazelle. Other threads use kernel-mode protocol stack.

    ```sh
    GAZELLE_BIND_PROCNAME=test GAZELLE_THREAD_NAME=test_thread LD_PRELOAD=/usr/lib64/liblstack.so ./test
    ```

### 6. Configuring Gazelle

- The **lstack.conf** file is used to specify the startup parameters of lstack. The default path is **/etc/gazelle/lstack.conf**. The parameters in the configuration file are as follows:

|Options|Value|Remarks|
|:---|:---|:---|
|dpdk_args|--socket-mem (mandatory)<br>--huge-dir (mandatory)<br>--proc-type (mandatory)<br>--legacy-mem<br>--map-perfect<br>-d|DPDK initialization parameter. For details, see the DPDK description.<br>**--map-perfect** is an extended feature. It is used to prevent the DPDK from occupying excessive address space and ensure that extra address space is available for lstack.<br>The **-d** option is used to load the specified .so library file.|
|listen_shadow| 0/1 | Whether to use the shadow file descriptor for listening. This function is enabled when there is a single listen thread and multiple protocol stack threads.|
|use_ltran| 0/1 | Whether to use ltran. This parameter is no longer supported.|
|num_cpus|"0,2,4 ..."|IDs of the CPUs bound to the lstack threads. The number of IDs is the number of lstack threads (less than or equal to the number of NIC queues). You can select CPUs by NUMA nodes.|
|low_power_mode|0/1|Whether to enable the low-power mode. This parameter is not supported currently.|
|kni_switch|0/1|Whether to enable the rte_kni module. The default value is **0**. This parameter is no longer supported.|
|unix_prefix|"string"|Prefix string of the Unix socket file used for communication between Gazelle processes. By default, this parameter is left blank. The value must be the same as the value of **unix_prefix** in **ltran.conf** of the ltran process that participates in communication, or the value of the **-u** option for `gazellectl`. The value cannot contain special characters and can contain a maximum of 128 characters.|
|host_addr|"192.168.xx.xx"|IP address of the protocol stack, which is also the IP address of the application.|
|mask_addr|"255.255.xx.xx"|Subnet mask.|
|gateway_addr|"192.168.xx.1"|Gateway address.|
|devices|"aa:bb:cc:dd:ee:ff"|MAC address for NIC communication. The NIC is used as the primary bond NIC in bond 1 mode.  |
|app_bind_numa|0/1|Whether to bind the epoll and poll threads of an application to the NUMA node where the protocol stack is located. The default value is 1, indicating that the threads are bound.|
|send_connect_number|4|Number of connections for sending packets in each protocol stack loop. The value is a positive integer.|
|read_connect_number|4|Number of connections for receiving packets in each protocol stack loop. The value is a positive integer.|
|rpc_number|4|Number of RPC messages processed in each protocol stack loop. The value is a positive integer.|
|nic_read_num|128|Number of data packets read from the NIC in each protocol stack cycle. The value is a positive integer.|
|bond_mode|-1|Bond mode. Currently, two network ports can be bonded. The default value is -1, indicating that the bond mode is disabled. bond1/4/6 is supported.|
|bond_slave_mac|"aa:bb:cc:dd:ee:ff;AA:BB:CC:DD:EE:FF"|MAC addresses of the bond network ports. Separate the MAC addresses with semicolons (;).|
|bond_miimon|10|Listening interval in bond mode. The default value is 10. The value ranges from 0 to 1500.|
|udp_enable|0/1|Whether to enable the UDP function. The default value is 1.|
|nic_vlan_mode|-1|Whether to enable the VLAN mode. The default value is -1, indicating that the VLAN mode is disabled. The value ranges from -1 to 4095. IDs 0 and 4095 are commonly reserved in the industry and have no actual effect.|
|tcp_conn_count|1500|Maximum number of TCP connections. The value of this parameter multiplied by **mbuf_count_per_conn** is the size of the mbuf pool applied for during initialization. If the value is too small, the startup fails. The value of (**tcp_conn_count** x **mbuf_count_per_conn** x 2048) cannot be greater than the huge page size.|
|mbuf_count_per_conn|170|Number of mbuf required by each TCP connection. The value of this parameter multiplied by **tcp_conn_count** is the size of the mbuf address pool applied for during initialization. If the value is too small, the startup fails. The value of (**tcp_conn_count** x **mbuf_count_per_conn** x 2048) cannot be greater than the huge page size.|

lstack.conf example:

```sh  
dpdk_args=["--socket-mem", "2048,0,0,0", "--huge-dir", "/mnt/hugepages-lstack", "--proc-type", "primary", "--legacy-mem", "--map-perfect"]

use_ltran=1
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

- The ltran mode is deprecated. If multiple processes are required, try the virtual network mode using SR-IOV network hardware.

### 7. Starting an Application

- Start the application.
    If the environment variable **LSTACK_CONF_PATH** is not used to specify the configuration file before the application is started, the default configuration file path **/etc/gazelle/lstack.conf** is used.

    ```sh
    export LSTACK_CONF_PATH=./lstack.conf
    LD_PRELOAD=/usr/lib64/liblstack.so  GAZELLE_BIND_PROCNAME=redis-server redis-server redis.conf
    ```

### 8. APIs

Gazelle wraps the POSIX interfaces of the application. The code of the application does not need to be modified.

### 9. Debugging Commands

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

The `-u` option specifies the prefix of the Unix socket for communication between Gazelle processes. The value of this parameter must be the same as that of **unix_prefix** in the **lstack.conf** file.

**Packet Capturing Tool**
The NIC used by Gazelle is managed by DPDK. Therefore, tcpdump cannot capture Gazelle packets. As a substitute, Gazelle uses gazelle-pdump provided in the dpdk-tools software package as the packet capturing tool. gazelle-pdump uses the multi-process mode of DPDK to share memory with the lstack process.  
[Usage](https://gitee.com/openeuler/gazelle/blob/master/doc/pdump.md)

**Thread Binding**
When the starting a lstack process, you can specify a thread bound to lstack using the environment variable **GAZELLE_THREAD_NAME**. When there are multiple threads in the service process, you can use this variable to specify the thread whose network interface needs to be managed by lstack. Other threads will use the kernel-mode protocol stack. By default, this parameter is left blank, that is, all threads in the process are bound.

### 10. Precautions

### 1. Location of the DPDK Configuration File

For the **root** user, the configuration file is stored in the **/var/run/dpdk** directory after the DPDK is started.
For a non-root user, the path of the DPDK configuration file is determined by the environment variable **XDG_RUNTIME_DIR**.

- If **XDG_RUNTIME_DIR** is not set, the DPDK configuration file is stored in **/tmp/dpdk**.
- If **XDG_RUNTIME_DIR** is set, the DPDK configuration file is stored in the path specified by **XDG_RUNTIME_DIR**.
- Note that **XDG_RUNTIME_DIR** is set by default on some servers.

## Restrictions

Restrictions of Gazelle are as follows:

### Function Restrictions

- Blocking **accept()** or **connect()** is not supported.
- A maximum of 1500 TCP connections are supported.
- Currently, only TCP, ICMP, ARP, IPv4, and UDP are supported.
- When a peer end pings Gazelle, the specified packet length must be less than or equal to 14,000 bytes.
- Transparent huge pages are not supported.
- VM NICs do not support multiple queues.

### Operation Restrictions

- By default, the command lines and configuration files provided by Gazelle requires **root** permissions. Privilege escalation and changing of file owner are required for non-root users.
- To bind the NIC from user-mode driver back to the kernel driver, you must exit Gazelle first.
- Memory huge pages cannot be remounted to subdirectories created in the mount point.
- The minimum hugepage memory of each application instance protocol stack thread is 800 MB.
- Gazelle supports only 64-bit OSs.
- The `-march=native` option is used when building the x86 version of Gazelle to optimize Gazelle based on the CPU instruction set of the build environment (Intel® Xeon® Gold 5118 CPU @ 2.30GHz). Therefore, the CPU of the operating environment must support the SSE4.2, AVX, AVX2, and AVX-512 instruction set extensions.
- The maximum number of IP fragments is 10 (the maximum ping packet length is 14,790 bytes). TCP does not use IP fragments.
- You are advised to set the **rp_filter** parameter of the NIC to 1 using the `sysctl` command. Otherwise, the Gazelle protocol stack may not be used as expected. Instead, the kernel protocol stack is used.
- The hybrid bonding of multiple types of NICs is not supported.
- The active/standby mode (bond1 mode) supports active/standby switchover only when a fault occurs at the link layer (for example, the network cable is disconnected), but does not support active/standby switchover when a fault occurs at the physical layer (for example, the NIC is powered off or removed).
- If the length of UDP packets to be sent exceeds 45952 (32 x 1436) bytes, increase the value of **send_ring_size** to at least 64.

## Precautions

You need to evaluate the use of Gazelle based on application scenarios.

The ltran mode and kni module is no longer supported due to changes in the dependencies and upstream community.

**Shared Memory**

- Current situation:
  The memory huge pages are mounted to the **/mnt/hugepages-lstack** directory. During process initialization, files are created in the **/mnt/hugepages-lstack** directory. Each file corresponds to a huge page, and the mmap function is performed on the files.
- Current mitigation measures
  The huge page file permission is **600**. Only the owner can access the files. The default owner is the **root** user. Other users can be configured.
  Huge page files are locked by DPDK and cannot be directly written or mapped.
- Caution
  Malicious processes belonging to the same user imitate the DPDK implementation logic to share huge page memory using huge page files and perform write operations to damage the huge page memory. As a result, the Gazelle program crashes. It is recommended that the processes of a user belong to the same trust domain.

**Traffic Limit**
Gazelle does not limit the traffic. Users can send packets at the maximum NIC line rate to the network, which may congest the network.

**Process Spoofing**
Ensure that all lstack processes are trusted.
