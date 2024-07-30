# gazelle网卡支持及使用

本文介绍用户态支持的常用网卡类型及其使用方法、部分网卡版本的升级步骤和gazelle环境部署时相关问题的解决办法。

## 物理网卡
### 常用网卡类型及使用说明
|厂家|驱动|nic型号|说明|
|:--|:--|:---|:---|
|Huawei|hinic|Hi1822 Family|①librte_net_hinic.so已经链接到liblstack.so；<br>②执行dpdk-devbind -b vfio-pci/igb_uio 网卡设备，使dpdk绑定网卡设备。|
|Hisilicon|hns3|HNS GE/10GE/25GE/50GE|①librte_net_hns3.so未链接到liblstack.so，配置文件dpdk_args需要使用-d加载；<br>②执行dpdk-devbind -b vfio-pci/igb_uio 网卡设备，使dpdk绑定网卡设备。|
|NVIDIA|mlx5_core|NVIDIA ConnectX-4<br>NVIDIA ConnectX-4 Lx<br>NVIDIA ConnectX-5<br>NVIDIA ConnectX-6<br>NVIDIA ConnectX-6 Dx<br>NVIDIA ConnectX-6 Lx<br>NVIDIA ConnectX-7<br>their VF in SR-IOV context.|①librte_net_mlx5.so未链接到liblstack.so，配置文件dpdk_args使用-d加载；<br>②mlx网卡不需要dpdk绑定网卡设备。|
|Intel|ixgbe<br>igb|ixgbe(82598, 82599, X520, X540, X550)<br>igb(82573, 82576, 82580, I210, I211, I350, I354, DH89xx)|①igb: librte_net_e1000.so未链接到liblstack.so，配置文件dpdk_args使用-d加载;<br>②ixgbe: librte_net_ixgbe.so已经链接到liblstack.so；<br>③均需要执行dpdk-devbind -b vfio-pci/igb_uio 网卡设备，使dpdk绑定网卡设备。|

注：<br>
① 可以在gazelle/src/lstack/Makefile中check LIBRTE_LIB中是否链接网卡对应的so，如已链接则可直接使用，未链接则-d加载。<br>
```
#网卡对应的so查询
rpm -ql dpdk|grep 驱动名关键词
eg:rpm -ql dpdk|grep mlx5
eg:rpm -ql dpdk|grep hinic
找到/usr/lib64/librte_net_xxxx.so
```
② 具体dpdk-devbind -b vfio-pci/igb_uio 网卡设备方法如下：
```
#vfio模块将硬件设备映射到用户空间，使用该驱动物理机内核需要支持IOMMU特性
#硬件支持硬件I/O虚拟化技术时，建议使用vfio-pci
modprobe vfio-pci

#若IOMMU不能使用，且VFIO支持noiommu
modprobe vfio enable_unsafe_noiommu_mode=1
modprobe vfio-pci

#其它情况，硬件不支持硬件I/O虚拟化技术时，可以使用igb_uio
modprobe igb_uio

#使用vfio-pci
dpdk-devbind -b vfio-pci enp3s0/设备pci 

#使用igb_uio
dpdk-devbind -b igb_uio enp3s0/设备pci
```
### 硬件虚拟化—vf网卡
vf直通网络模式的docker容器中，gazelle支持mlx系列网卡使用，暂不支持hinic系列网卡。容器场景mlx网卡vf直通搭建方法如下：

```
#方法一
① 下载docker-sriov-plugin插件
https://gitee.com/mellanox/docker-sriov-plugin，编译插件镜像；
或者配代理直接
docker pull rdma/sriov-plugin；
② 创建vf
echo 2 > /sys/class/net/enp129s0f0np0/device/sriov_numvfs
③ 加载插件镜像
docker load -i sriov-plugin.tar；
④ 运行插件
docker run -v /run/docker/plugins:/run/docker/plugins -v /etc/docker:/etc/docker -v /var/run:/var/run --net=host --privileged，执行完成后并不会退出，将作为控制台输出日志信息；
⑤ 创建sriov模式的docker网络
docker network create -d sriov --subnet=194.168.1.0/24 -o netdevice=enp7s0f0np0 mysriov
⑥ 创建vf直通docker容器
docker run ... --net=mysriov ...
```
```
#方法二
① 创建vf
echo 2 > /sys/class/net/enp129s0f0np0/device/sriov_numvfs
② 创建bridge网络模式的容器
docker run ... --net=bridge ...
③ 将vf网卡挂到docker命名空间
pid=$(docker inspect -f '{{.State.Pid}}' openeuler-docker) #这里是容器的名字
mkdir -p /var/run/netns
ln -s /proc/${pid}/ns/net /var/run/netns/${pid}
ip link set enp129s0f0v0 netns ${pid} #这里enp129s0f0v0是vf网卡的名字
```

## 虚拟网卡
|驱动|说明|使用方法|
|:--|:---|:---|
|e1000|模拟1 Gbit intel 82545EM网卡，绝大多数VMware虚机默认选项|①librte_net_e1000.so未链接到liblstack.so，配置文件中dpdk_args使用-d加载；<br>②执行dpdk-devbind -b vfio-pci/igb_uio 网卡设备，使dpdk绑定网卡设备。|
|e1000e|模拟1 Gbit intel 82574网卡|①librte_net_e1000e.so未链接到liblstack.so，配置文件中dpdk_args使用-d加载；<br>②执行dpdk-devbind -b vfio-pci/igb_uio 网卡设备，使dpdk绑定网卡设备。|
|vmxnet3|模拟10 Gbit网卡，用于VMware虚拟化平台|①librte_net_vmxnet3.so未链接到liblstack.so，配置文件中dpdk_args使用-d加载；<br>②执行dpdk-devbind -b vfio-pci/igb_uio 网卡设备，使dpdk绑定网卡设备。|

## 网卡升级
### NVIDIA Mellanox ConnectX系列网卡
1. 下载MLNX_OFED驱动 <br>
下载网址：https://network.nvidia.com/products/infiniband-drivers/linux/mlnx_ofed/ <br>
注意根据官方Note选择合适的驱动版本，如MLNX_OFED 5.8-x LTS should be used by customers who would like to utilize NVIDIA ConnectX-4 onwards adapter cards.当我们使用CX4或者CX5时，可以选择MLNX_OFED 5.8-x版本驱动。

2. 安装依赖
```
yum install -y tk make tcsh pciutils-devel lsof gcc kernel-devel
yum install -y python3-devel automake rpm-build autoconf createrepo elfutils-devel lsof libtool
```
3. 升级安装
```
#rdma-core存在会报错，需要先卸载
rpm -q rdma-core && yum remove -y rdma-core
tar xf /home/MLNX*.tgz -C /home
rm -f /home/MLNX*.tgz
cd /home/MLNX*

./mlnxofedinstall --dpdk --add-kernel-support --skip-unsupported-devices-check
dracut -f
rmmod rpcrdma ib_srpt ib_isert hns_roce_hw_v2 i40iw xprtrdma svcrdma
/etc/init.d/openibd restart
modprobe mlx5_core
modinfo mlx5_core | grep "filename:" 
```
### 其他网卡
暂不涉及。

## 常见问题及解决方法
### 1. 物理机/虚拟机场景，dpdk未绑定网卡设备<br>
```
LSTACK: create_control_thread:171 create control_easy_thread success
LSTACK: stack_group_init_mempool:562 config::num_cpu=1 num_process=1
LSTACK: ethdev_port_id:369 No NIC is matched
EAL: Error - exiting with code: 1
  Cause: gazelle_network_init:306 init_dpdk_ethdev failed
```
解决方法：<br>①先ip a查看网卡设备的mac地址，写入lstack.conf中device；<br>②执行dpdk-devbind -b vfio-pci/igb_uio 网卡设备；<br>③dpdk-devbind -s查看Network devices using DPDK-compatible driver列表是否绑定成功。

### 2. 物理机/虚拟机/容器场景，网卡设备和gazelle绑定的cpu不在同一个numa上<br>
```
EAL: VFIO support initialized
EAL: Probe PCI driver: mlx5_pci (15b3:1015) device: 0000:81:00.0 (socket 1)
mlx5_common: Failed to initialize global MR share cache.
EAL: Requested device 0000:81:00.0 cannot be used
EAL: Probe PCI driver: mlx5_pci (15b3:1015) device: 0000:81:00.1 (socket 1)
mlx5_common: Failed to initialize global MR share cache.
EAL: Requested device 0000:81:00.1 cannot be used
TELEMETRY: No legacy callbacks, legacy socket not created
LSTACK: create_control_thread:171 create control_easy_thread success
LSTACK: stack_group_init_mempool:562 config::num_cpu=1 num_process=1
LSTACK: ethdev_port_id:369 No NIC is matched
EAL: Error - exiting with code: 1
  Cause: gazelle_network_init:306 init_dpdk_ethdev failed
```
解决方法：<br>
①给网卡所在的节点分配大页内存
`echo 1024 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages`
①或者把gazelle使用的cpu改到和网卡同一个numa上，需要修改lstack.conf中num_cpus和dpdk_args(大页内存分配)

### 3. 容器场景，gazelle使用的cpu不在容器启动使用的cpu范围内<br>
```
EAL: VFIO support initialized
EAL: FATAL: Cannot set affinity
EAL: Cannot set affinity
EAL: Error - exiting with code: 1
  Cause: create_control_thread:164 dpdk_eal_init failed ret=-1 errno=2
```
解决方法：<br>
①修改lstack.conf中num_cpus为容器使用的cpu。

### 4. 容器+vf直通网络模式场景，hinic网卡，nic mac与lstack.conf中mac不一致<br>
```
LSTACK: create_control_thread:171 create control_easy_thread success
LSTACK: stack_group_init_mempool:562 config::num_cpu=1 num_process=1
LSTACK: ethdev_port_id:363 nic mac:02:09:c0:f5:05:bc not match
LSTACK: ethdev_port_id:369 No NIC is matched
EAL: Error - exiting with code: 1
  Cause: gazelle_network_init:306 init_dpdk_ethdev failed
```
解决方法：<br>
①暂不支持hinic网卡容器vf直通。

### 5. 容器内没有vfio驱动，或者设备目录未共享，dpdk绑定网卡设备失败
```
EAL: VFIO support initialized
EAL: Failed to open VFIO group 49
EAL: 0000:17:00.0 not managed by VFIO driver, skipping
TELEMETRY: No legacy callbacks, legacy socket not created
testpmd: No probed ethernet devices
EAL: Error - exiting with code: 1
  Cause: No cores defined for forwarding
Check the core mask argument
```
解决方法：<br>
① 容器run时加-v /lib/modules/:/lib/modules/ -v /dev:/dev共享路径；<br>
② 或者先stop容器，在容器外使用dpdk-devbind -b命令进行网卡绑定，绑定成功后再start容器。


