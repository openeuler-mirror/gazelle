 # Gazelle User Guide
 
 ## Installation
 Configure the OpenEuler yum repository and install directly using the yum command:
 ```sh
 # dpdk >= 21.11-2
 yum install dpdk
 yum install libconfig
 yum install numactl
 yum install libboundscheck
 yum install libpcap
 yum install gazelle
 ```
 
 ## Usage
 Configure the operating environment. The steps for accelerating applications using Gazelle are as follows:
 ### 1. Install the ko with root privileges
 Select the ko to use based on the actual situation. It provides virtual network ports and binds the network card to user mode functions.
 If you use the virtual network port function, use rte_kni.ko
 
 ``` sh
 modprobe rte_kni carrier="on"
 ```
 
 Configure NetworkManager not to manage the kni network card
 ```
 [root@localhost ~]# cat /etc/NetworkManager/conf.d/99-unmanaged-devices.conf
 [keyfile]
 unmanaged-devices=interface-name:kni
 [root@localhost ~]# systemctl reload NetworkManager
 ```
 
 Bind the network card from the kernel driver to the user mode driver ko. Select one according to the actual situation. mlx4 and mlx5 network cards do not need to bind vfio or uio drivers.
 ``` sh
 # If IOMMU can be used
 modprobe vfio-pci
 
 # If IOMMU cannot be used, and VFIO supports noiommu
 modprobe vfio enable_unsafe_noiommu_mode=1
 modprobe vfio-pci
 
 # Other cases
 modprobe igb_uio
 ```
 
 ### 2. Bind the network card to dpdk
 Bind the network card to the driver selected in step 1. Provide network card resource access interface for user mode network card driver.
 ``` sh
 # Use vfio-pci
 dpdk-devbind -b vfio-pci enp3s0 
 
 # Use igb_uio
 dpdk-devbind -b igb_uio enp3s0
 ```
 
 ### 3. Huge page memory configuration
 Gazelle uses huge pages to improve efficiency. Use root privileges to configure the system to reserve huge pages, and any page size can be used. Since each page of memory requires an fd, when using a larger memory, it is recommended to use a 1G page to avoid occupying too many fds.
 According to the actual situation, select a page size and configure enough huge pages. The steps to configure huge pages are as follows:
 ``` sh
 # Configure 2M huge pages: Configure 2M * 1024 = 2G on node0
 echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
 
 # Configure 1G huge pages: Configure 1G * 5 = 5G on node0
 echo 5 > /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages
 
 # View configuration results
 grep Huge /proc/meminfo
 ```
 
 ### 4. Mount huge pages
 Create two directories for the lstack process and ltran process to access huge pages. The operation steps are as follows:
 ``` sh
 mkdir -p /mnt/hugepages-ltran
 mkdir -p /mnt/hugepages-lstack
 chmod -R 700 /mnt/hugepages-ltran
 chmod -R 700 /mnt/hugepages-lstack
 # Note: /mnt/hugepages-ltran and /mnt/hugepages-lstack must mount huge pages of the same pagesize.
 mount -t hugetlbfs nodev /mnt/hugepages-ltran -o pagesize=2M
 mount -t hugetlbfs nodev /mnt/hugepages-lstack -o pagesize=2M
 ```
 
 ### 5. Application uses Gazelle
 There are two ways to use Gazelle, choose one according to your needs
 - Recompile the application and link the Gazelle library
 Modify the application makefile file to link liblstack.so, as shown below:
 ```
 # Add Gazelle's Makefile to makefile
 -include /etc/gazelle/lstack.Makefile
 
 # Compile and add the LSTACK_LIBS variable
 gcc test.c -o test ${LSTACK_LIBS}
 ```
 
 - Use LD_PRELOAD to load the Gazelle library
 The GAZELLE_BIND_PROCNAME environment variable specifies the process name, and LD_PRELOAD specifies the Gazelle library path
 ```
 GAZELLE_BIND_PROCNAME=test LD_PRELOAD=/usr/lib6
 ```
 
 ### 6. Configuration File
 - The lstack.conf file is used to specify the startup parameters for lstack, with the default path being /etc/gazelle/lstack.conf. The configuration file parameters are as follows:
 
 | Option | Parameter Format | Description |
|:---|:---|:---|
| dpdk_args | --socket-mem (mandatory)<br>--huge-dir (mandatory)<br>--proc-type (mandatory)<br>--legacy-mem<br>--map-perfect<br>-d<br>etc. | DPDK initialization parameters, refer to DPDK documentation. <br>For PMDs not linked to liblstack.so, use -d to load them, such as libnet_mlx5.so. |
| use_ltran | 0/1 | Whether to use ltran. |
| listen_shadow | 0/1 | Whether to use shadow FD listening. Used when there are multiple protocol stack threads for a single listen thread. |
| num_cpus | "0,2,4 ..." | CPU numbers to which lstack threads are bound. The number of IDs corresponds to the number of lstack threads (which is less than or equal to the number of queues per NIC). CPUs can be selected according to NUMA. |
| app_bind_numa | 0/1 | Whether epoll and poll threads of the application are bound to the NUMA where the protocol stack resides. Default is 1, meaning bound. |
| app_exclude_cpus | "7,8,9 ..." | CPU numbers to which epoll and poll threads of the application are not bound. Only effective when app_bind_numa = 1. |
| low_power_mode | 0/1 | Whether to enable low power mode. Currently not supported. |
| kni_swith | 0/1 | rte_kni switch, default is 0. Can only be enabled when not using ltran. |
| unix_prefix | "string" | Prefix string for inter-process communication using UNIX sockets. Default is empty and should be consistent with the unix_prefix in ltran.conf or the -u parameter of gazellectl. Cannot contain special characters, with a maximum length of 128. |
| host_addr | "192.168.xx.xx" | IP address of the protocol stack, must be consistent with the "bind" field in the redis-server configuration file. |
| mask_addr | "255.255.xx.xx" | Mask address. |
| gateway_addr | "192.168.xx.1" | Gateway address. |
| devices | "aa:bb:cc:dd:ee:ff" | MAC address for communication via the NIC, must be consistent with the bond_macs configuration in ltran.conf; in lstack bond1 mode, specify the primary interface of bond1, taking one of the bond_slave_mac values. |
| send_connect_number | 4 | Positive integer indicating the number of connections processed per cycle in the protocol stack for packet transmission. |
| read_connect_number | 4 | Positive integer indicating the number of connections processed per cycle in the protocol stack for packet reception. |
| rpc_number | 4 | Positive integer indicating the number of RPC messages processed per cycle in the protocol stack. |
| nic_read_num | 128 | Positive integer indicating the number of data packets read from the NIC per cycle in the protocol stack. |
| tcp_conn_count | 1500 | Maximum number of TCP connections. This parameter multiplied by mbuf_count_per_conn is the size of the mbuf pool allocated during initialization. If set too small, startup may fail. tcp_conn_count * mbuf_count_per_conn * 2048 bytes must not exceed the size of the huge page. |
| mbuf_count_per_conn | 170 | Number of mbufs required per TCP connection. This parameter multiplied by tcp_conn_count is the size of the mbuf address pool allocated during initialization. If set too small, startup may fail. tcp_conn_count * mbuf_count_per_conn * 2048 bytes must not exceed the size of the huge page. |
| nic_rxqueue_size | 4096 | Depth of the NIC receive queue, range is 512-8192, default is 4096. |
| nic_txqueue_size | 2048 | Depth of the NIC transmit queue, range is 512-8192, default is 2048. |
| nic_vlan_mode | -1 | VLAN mode switch, variable value is the VLAN ID, range is -1 to 4094, -1 means disabled, default is -1. |
| bond_mode | n | Bond mode, currently supports ACTIVE_BACKUP/8023AD/ALB, corresponding values are 1/4/6; when set to -1 or NULL, it means bond is not configured. |
| bond_slave_mac | "aa:bb:cc:dd:ee:ff;dd:aa:cc:dd:ee:ff" | MAC addresses of the two sub-interfaces used to form a bond. |
| bond_miimon | n | Link monitoring time in milliseconds, range is 1 to 2^31 - 1, default is 10ms. |

```conf
lstack.conf example:
```conf
dpdk_args=["--socket-mem", "2048,0,0,0", "--huge-dir", "/mnt/hugepages-lstack", "--proc-type", "primary", "--legacy-mem", "--map-perfect"]

use_ltran=1
kni_switch=0

low_power_mode=0

num_cpus="2,22"

host_addr="192.168.1.10"
mask_addr="255.255.255.0"
gateway_addr="192.168.1.1"
devices="aa:bb:cc:dd:ee:ff"

send_connect_number=4
read_connect_number=4
rpc_number=4
nic_read_num=128
tcp_conn_count=1500
mbuf_count_per_conn=170
```

ltran.conf is used to specify the parameters for starting ltran, with the default path being /etc/gazelle/ltran.conf. When using ltran, set use_ltran=1 in lstack.conf and configure the parameters as follows:

| Functional Category | Option | Parameter Format | Description |
|:---|:---|:---|:---|
| kit | forward_kit | "dpdk" | Specifies the NIC transmit/receive module.<br>Reserved field, currently not used. |
|| forward_kit_args | -l<br>--socket-mem (required)<br>--huge-dir (required)<br>--proc-TYPE (required)<br>--legacy-mem (required)<br>--map-perfect (required)<br>-d<br>etc. | DPDK initialization parameters, refer to DPDK documentation.<br>Note: --map-perfect is an extended feature used to prevent DPDK from occupying extra address space, ensuring ltran has additional address space allocated to lstack.<br>For PMDs not linked to ltran, -d must be used for loading, such as librte_net_mlx5.so.<br>-l binds CPU cores that are different from those bound to lstack, otherwise performance may drastically decrease.<br> |
| kni | kni_switch | 0/1 | rte_kni switch, default is 0 |
| unix | unix_prefix | "string" | Unix socket file prefix string used for communication between gazelle processes, default is empty, consistent with unix_prefix in the communicating lstack.conf or the -u parameter of gazellectl |
| dispatcher | dispatch_max_clients | n | Maximum number of clients supported by ltran.<br>1. In a multi-process single-thread scenario, the number of supported lstack instances is no more than 32, with one network thread per lstack instance.<br>2. In a single-process multi-thread scenario, only 1 lstack instance is supported, with the number of network threads per lstack instance no more than 32. |
|| dispatch_subnet | 192.168.xx.xx | Subnet mask indicating the subnet segment where ltran can recognize IP addresses. The parameter is an example; configure the subnet according to the actual value. |
|| dispatch_subnet_length | n | Subnet length indicating the length of the subnet that ltran can recognize. For example, when the length is 4, it covers IP addresses from 192.168.1.1 to 192.168.1.16 |
| bond | bond_mode | n | Bonding mode, currently only supports Active Backup (Mode 1), with a value of 1 |
|| bond_miimon | n | Bond link monitoring time, in milliseconds, with a range from 1 to 2^64 - 1 - (1000 * 1000) |
|| bond_ports | "0xaa" | DPDK NICs used, where 0x1 represents the first one |
|| bond_macs | "aa:bb:cc:dd:ee:ff" | MAC addresses bound to the NICs, must be consistent with the MAC address of kni |
|| bond_mtu | n | Maximum transmission unit, default is 1500, cannot exceed 1500, minimum value is 68, cannot be lower than 68 |

ltran.conf example:
```conf
forward_kit_args="-l 0,1 --socket-mem 1024,0,0,0 --huge-dir /mnt/hugepages-ltran --proc-type primary --legacy-mem --map-perfect --syslog daemon"
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
### 7. Starting the Application
- Starting the ltran process  
If it's a single process and the network card supports multiple queues, then directly use the network card's multiple queues to distribute packets to each thread, without starting the ltran process. Set use_ltran=0 in lstack.conf.  
If not specifying the configuration file with -config-file when starting ltran, it will use the default path /etc/gazelle/ltran.conf.
``` sh
ltran --config-file ./ltran.conf
```
- Starting the application  
Before starting the application, if the LSTACK_CONF_PATH environment variable is not used to specify the configuration file, the default path /etc/gazelle/lstack.conf is used.
``` sh
export LSTACK_CONF_PATH=./lstack.conf
LD_PRELOAD=/usr/lib64/liblstack.so GAZELLE_BIND_PROCNAME=redis-server redis-server redis.conf
```

### 8. API
Gazelle wraps the POSIX interfaces of applications, so no code modifications are needed for the applications.

### 9. Debugging Commands
- The gazellectl ltran xxx command is not supported when not using ltran mode.
- The -u parameter specifies the unix socket prefix for Gazelle inter-process communication, which must be consistent with the unix_prefix setting in the communicating ltran.conf or lstack.conf.
- For UDP connections, currently, the gazellectl lstack xxx command only supports without LSTACK_OPTIONS parameters.
```
Usage: gazellectl [-h | help]
  or:  gazellectl ltran  {quit | show} [LTRAN_OPTIONS] [time] [-u UNIX_PREFIX]
  or:  gazellectl lstack show {ip | pid} [LSTACK_OPTIONS] [time] [-u UNIX_PREFIX]

  quit            ltran process exit

  where  LTRAN_OPTIONS :=
                  show all ltran statistics
  -r, rate        show ltran statistics per second
  -i, instance    show ltran instance register info
  -b, burst       show ltran NIC packet length per second
  -t, table       {socktable | conntable}  show ltran sock or conn table
  -l, latency     show ltran latency

  where  LSTACK_OPTIONS :=
                  show all lstack statistics
  -r, rate        show lstack statistics per second
  -s, snmp        show lstack snmp
  -c, connect     show lstack connect
  -l, latency     show lstack latency
  -x, xstats      show lstack xstats
  -k, nic-features     show state of protocol offload and other features
  -a, aggregation [time]   show lstack send/recv aggregation
  set:
  loglevel        {error | info | debug}  set lstack log level
  lowpower        {0 | 1}  set low power mode
  [time]          measure latency time, default 1S
```

**Packet Capture Tool**  
The network cards used by Gazelle are managed by DPDK, so traditional tcpdump cannot capture packets from Gazelle. Instead, Gazelle uses the gazelle-pdump tool from the dpdk-tools package for packet capture. This tool uses DPDK's multi-process mode and shares memory with lstack/ltran processes. In ltran mode, gazelle-pdump can only capture packets that communicate directly with the network card. By using tcpdump's packet filtering, it is possible to filter packets specific to an lstack.
[Detailed usage](https://gitee.com/openeuler/gazelle/blob/master/doc/pdump.md)

### 10. Usage Notes
#### 1. Location of dpdk Configuration File
The location of the dpdk configuration file depends on the user's privileges:
- If running as the root user, the dpdk configuration file will be placed in the /var/run/dpdk directory after dpdk starts.
- If running as a non-root user, the location of the dpdk configuration file is determined by the XDG_RUNTIME_DIR environment variable:
  - If XDG_RUNTIME_DIR is empty, the dpdk configuration file will be placed in the /tmp/dpdk directory.
  - If XDG_RUNTIME_DIR is not empty, the dpdk configuration file will be placed in the directory specified by the XDG_RUNTIME_DIR variable.
  - Note that some machines may have XDG_RUNTIME_DIR set by default.

#### 2. Impact of retbleed Vulnerability Patch on gazelle Performance
- The kernel version 5.10.0-60.57.0.85 introduced the retbleed vulnerability patch, which causes a performance degradation in gazelle on X86 architecture. To mitigate the performance loss caused by this CVE, users can add **retbleed=off mitigations=off** to the boot parameters. Users can choose whether to mitigate this CVE based on their product characteristics, but it is not mitigated by default for security reasons.
- In the testing scenario where the sender is in kernel mode and the receiver is in user mode using ltran, with packets of 1024 bytes, the performance decreased from 17000 Mb/s to 5000 Mb/s.
- Affected versions include openEuler-22.03-LTS (kernel version equal to or higher than 5.10.0-60.57.0.85) and subsequent SP versions.
- For more details, please refer to: https:/gitee.com/openeuler/kernel/pulls/110

## Constraints

There are certain constraints when using Gazelle:
#### Functional Constraints
- Blocking modes for accept or connect are not supported.
- A maximum of 1500 TCP connections is supported.
- Currently, only TCP, ICMP, ARP, and IPv4 protocols are supported.
- When pinging Gazelle from the peer, the packet length must be less than or equal to 14792 bytes.
- Transparent huge pages are not supported.
- ltran does not support mixing multiple types of bonded network cards.
- In ltran's bond1 active-backup mode, only link layer failure is supported (e.g., cable disconnection), not physical layer failure (e.g., NIC power off, unplugging NIC).
- Virtual machine network cards do not support multi-queue.
#### Operational Constraints
- The provided command-line and configuration files default to root privileges. Non-root users need to elevate privileges and change file ownership before use.
- Returning the user-space network card to the kernel driver requires exiting Gazelle first.
- Huge pages cannot be created in subdirectories under the mount point for remounting.
- ltran requires a minimum of 1064MB of huge page memory.
- Each application instance's protocol stack thread requires a minimum of 800MB of huge page memory.
- Only 64-bit systems are supported.
- Building the x86 version of Gazelle uses the -march=native option, optimizing for the CPU architecture of the build environment (Intel® Xeon® Gold 5118 CPU @ 2.30GHz instruction set). The running environment's CPU must support SSE4.2, AVX, AVX2, and AVX-512 instruction sets.
- The maximum number of IP fragments for IP datagram reassembly is 10 (ping maximum packet length 14792 bytes), and TCP protocol does not use IP fragmentation.
- Ensure sysctl configures the network card's rp_filter parameter to 1; otherwise, Gazelle protocol stack may not be used as expected, and the kernel protocol stack may still be used.
- Without using ltran mode, KNI interfaces cannot be configured to only support local communication and require NetworkManager to be configured not to manage KNI interfaces before starting.
- The IP and MAC addresses of virtual KNI interfaces must match those specified in the lstack.conf configuration file.
- When sending UDP packets longer than 45952 (32 * 1436) bytes, the send_ring_size needs to be increased to at least 64.

## Risk Alert

Gazelle may have the following security risks, and users need to assess the risks based on their usage scenarios.

**Shared Memory**  
- Current Status  
  Huge pages are mounted to the /mnt/hugepages-lstack directory, and processes linking liblstack.so create files in the /mnt/hugepages-lstack directory during initialization, with each file corresponding to 2MB huge pages and mmap-ing these files. ltran, upon receiving registration information from lstask, also mmap-s files in the directory based on the huge page memory configuration, achieving shared huge page memory.
  ltran operates similarly with huge page memory in the /mnt/hugepages-ltran directory.
- Current Mitigation Measures  
  Huge page files have permissions set to 600, accessible only by the OWNER user, defaulting to the root user, and can be configured to other users.
  Huge page files have DPDK file locks, preventing direct writing or mapping.
- Risk Points  
  Malicious processes from the same user domain can mimic DPDK logic to share huge page memory via shared files, causing damage to huge page memory and leading to Gazelle program crashes. It is recommended that processes under the user belong to the same trust domain.

**Traffic Limitation**  
Gazelle does not enforce traffic limitations, allowing users to send packets at the maximum network card line speed, potentially causing network traffic congestion.

**Process Impersonation**  
Legitimately registered lstack processes with ltran can impersonate each other (Process A can impersonate Process B) to send fake messages to ltran, altering ltran's forwarding control information, causing communication anomalies in Process B, and potentially leaking information from Process B to Process A. It is recommended that all lstack processes are trusted processes.
