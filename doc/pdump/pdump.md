# 使用pdump抓包
pdump作为gazelle的从进程，共享网卡驱动收发队列，获取到报文并按pcap格式写入文件，该文件可用wireshark查看。

openEuler的dpdk软件包中提供了gazelle-pdump命令对Gazelle抓包。  

## 常用参数说明：

|选项|参数值示例|说明|
|:---|:---|:---|
|--file-prefix|gazelle|指定主进程共享目录位置<br>需要和lstack.conf或ltran.conf中的-file-prefix保持一致|
|device_id|0000:01:00.0|抓包网卡的PCI地址<br>需要和dpdk-devbind -s命令查询的结果一致|
|rx-dev|/root/capture-rx.pcap|网卡接收的数据包存放的文件位置|
|tx-dev|/root/capture-tx.pcap|网卡发送的数据包存放的文件位置，如果它配置的路径与rx-dev的相同，则文件中会同时包含收发的数据包|

更多参数解释：
```
gazelle-pdump --help
```

## 使用示例：
```
gazelle-pdump --file-prefix gazelle -- --pdump 'device_id=0000:01:00.0,queue=*,rx-dev=/root/capture-rx.pcap,tx-dev=/root/capture-tx.pcap'
```
<img src="pdump.png" alt=scene style="zoom:100%"> 

使用ctrl+C停止抓包，抓包完成后数据包将保存为pcap文件格式，它可以被`tcpdump`命令进一步处理。

<img src="pdump-tcpdump.png" alt=scene style="zoom:50%"> 

下面的命令将过滤数据包中源IP为`192.168.1.10`的数据包：
```
tcpdump -r /root/capture.pcap src host 192.168.1.10 -w /root/filter-capture.pcap
```

## 常见问题及解决方案：
### 报错信息1
```
Device 0000:02:08.0 is not driven by the primary process
EAL: Requested device 0000:02:08.0 cannot be used
Port 1 MAC: 02 70 63 61 70 00
PDUMP: client request for pdump enable/disable failed
PDUMP: client request for pdump enable/disable failed
PDUMP: client request for pdump enable/disable failed
```
原因：lstack/ltran使用的网卡和gazelle-pdump指定的网卡不一致，需要重新检查device_id参数。

### 报错信息2
```
EAL: Multi-process socket /var/run/dpdk/(null)/mp_socket_3884565_28c50010577fe
EAL: failed to send to (/var/run/dpdk/(null)/mp_socket) due to Connection refused
EAL: Fail to send request /var/run/dpdk/(null)/mp_socket:bus_vdev_mp
vdev_scan(): Failed to request vdev from primary
EAL: Selected IOVA mode 'PA'
EAL: Probing VFIO support...
EAL: failed to send to (/var/run/dpdk/(null)/mp_socket) due to Connection refused
EAL: Cannot send message to primary
EAL: error allocating rte services array
EAL: FATAL: rte_service_init() failed
EAL: rte_service_init() failed
```
原因：gazelle-pdump指定的共享内存路径中没有相应的文件，需要重新检查--file-prefix参数。

### 报错信息3
```
EAL: Failed to hotplug add device
EAL: Error - exiting with code: 1
  Cause: vdev creation failed:create_mp_ring_vdev:700
```
原因：`lstack`/`ltran`没有链接到`librte_pmd_pcap.so(dpdk-19.11)`/`librte_net_pcap.so(dpdk-21.11)`动态库，需要重新检查编译的Makefile，解决方法如下。
- 修改dpdk.spec加入PDUMP的编译选项，重新编译dpdk
%build
```
sed -ri 's,(LIBRTE_PMD_PCAP=).*,\1y,'      %{target}/.config
```


- 使用gazelle相同的编译参数编译dpdk-pdump
pdump的源文件位于dpdk的目录下：`app/pdump/main.c `

- 示例编译命令（基于dpdk-19.11）：
```
cc -O0 -g -fno-strict-aliasing -mssse3 -I/usr/include/dpdk -fstack-protector-strong -Werror -Wall -fPIC   -c -o main.o main.c
```

- 示例链接命令（基于dpdk-19.11）：
```
cc -lm -lpthread -lrt -lnuma -lconfig -lboundscheck -Wl,--whole-archive /usr/lib64/librte_pci.so /usr/lib64/librte_bus_pci.so /usr/lib64/librte_cmdline.so /usr/lib64/librte_hash.so /usr/lib64/librte_mempool.so /usr/lib64/librte_mempool_ring.so /usr/lib64/librte_timer.so /usr/lib64/librte_eal.so /usr/lib64/librte_ring.so /usr/lib64/librte_mbuf.so /usr/lib64/librte_kni.so /usr/lib64/librte_gro.so /usr/lib64/librte_pmd_ixgbe.so /usr/lib64/librte_kvargs.so /usr/lib64/librte_pmd_hinic.so /usr/lib64/librte_pmd_i40e.so /usr/lib64/librte_pmd_virtio.so /usr/lib64/librte_bus_vdev.so /usr/lib64/librte_net.so /usr/lib64/librte_ethdev.so /usr/lib64/librte_pdump.so /usr/lib64//librte_pmd_pcap.so main.o -Wl,--no-whole-archive -Wl,--whole-archive -Wl,--no-whole-archive -o gazelle-pdump
```

保证链接命令中的动态库和liblstack.so使用的编译选项是相同的，就是Makefile里的LIBRTE_LIB库
