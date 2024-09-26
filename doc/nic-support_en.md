# Gazelle NIC Support and Usage

This document describes the common NIC types supported by the user mode and how to use the NICs, how to upgrade some NIC versions, and how to solve problems that may occur during the deployment of the Gazelle environment.

## Physical network adapter
### Common Network Adapter Types and Usage
| Manufacturer | Driver | NIC model | Description |
|:--|:--|:---|:---|
|Huawei|hinic|Hi1822 Family|①librte_net_hinic.so is linked to liblstack.so.<br>②Run the dpdk-devbind -b vfio-pci/igb_uio command to bind the dpdk to the network adapter.|
|Hisilicon|hns3|HNS GE/10GE/25GE/50GE|①librte_net_hns3.so is not linked to liblstack.so. The dpdk_args configuration file needs to be loaded using -d.<br>②Run the dpdk-devbind -b vfio-pci/igb_uio command to bind the dpdk to the network adapter.|
|NVIDIA|mlx5_core|NVIDIA ConnectX-4<br>NVIDIA ConnectX-4 Lx<br>NVIDIA ConnectX-5<br>NVIDIA ConnectX-6<br>NVIDIA ConnectX-6 Dx<br>NVIDIA ConnectX-6 Lx<br>NVIDIA ConnectX-7<br>their VF in SR-IOV context.|①librte_net_mlx5.so is not linked to liblstack.so. The configuration file dpdk_args is loaded using -d.<br>②The mlx network adapter does not need to be bound to the dpdk.|
|Intel|ixgbe<br>igb|ixgbe(82598, 82599, X520, X540, X550)<br>igb(82573, 82576, 82580, I210, I211, I350, I354, DH89xx)|①igb: librte_net_e1000.so is not linked to liblstack.so. The configuration file dpdk_args is loaded using -d.<br>②ixgbe: librte_net_ixgbe.so has been linked to liblstack.so.<br>③You need to run the dpdk-devbind -b vfio-pci/igb_uio command to bind the dpdk to the network adapter.|

Notes:<br>
① You can check whether the .so file corresponding to the network adapter is linked in the LIBRTE_LIB file in the gazelle/src/lstack/Makefile directory. If the file is linked, you can directly use the file. If the file is not linked, run the -d command to load the file.<br>
```
# How to query the so file corresponding to the NIC
rpm -ql dpdk|grep {Driver Name Keyword}
eg:rpm -ql dpdk|grep mlx5
eg:rpm -ql dpdk|grep hinic
get /usr/lib64/librte_net_xxxx.so
```
② DPDK Network Adapter Binding:
```
#The VFIO module maps hardware devices to the user space. To use this driver, the kernel of the physical machine must support the IOMMU feature.
#If hardware I/O virtualization is supported, vfio-pci is recommended.
modprobe vfio-pci

#If IOMMU cannot be used and VFIO supports noiommu:
modprobe vfio enable_unsafe_noiommu_mode=1
modprobe vfio-pci

#In other cases, if the hardware does not support the hardware I/O virtualization technology, igb_uio can be used.
modprobe igb_uio

#Use vfio-pci
dpdk-devbind -b vfio-pci enp3s0/device_pci 

#Use igb_uio
dpdk-devbind -b igb_uio enp3s0/device_pci
```
### Hardware Virtualization – VF NIC
In the Docker container in VF passthrough network mode, gazelle supports mlx and hinic series NICs. Other NICs are not verified.
#### To set up a VF passthrough system for the MLX NIC in the container scenario, perform the following steps:
```
#Method1
① Downloading the docker-sriov-plugin Plug-in
https://gitee.com/mellanox/docker-sriov-plugin, and then compile the plug-in image.
Alternatively, configure a proxy to download the image.
docker pull rdma/sriov-plugin
② create vf
echo 2 > /sys/class/net/enp129s0f0np0/device/sriov_numvfs
③ load plugin image
docker load -i sriov-plugin.tar；
④ run plugin
docker run -v /run/docker/plugins:/run/docker/plugins -v /etc/docker:/etc/docker -v /var/run:/var/run --net=host --privileged IMAGE ID，IMAGE ID is an image of the plugin. After the execution is complete, IMAGE ID does not exit and functions as the console to output log information.
⑤ Creating a Docker Network in SR-IOV Mode
docker network create -d sriov --subnet=194.168.1.0/24 -o netdevice=enp7s0f0np0 mysriov
⑥ Creating a vf Passthrough Docker Container
docker run ... --net=mysriov ...
```
```
#Method2
① Create VF
echo 2 > /sys/class/net/enp129s0f0np0/device/sriov_numvfs
② Creating a Container in Bridge Network Mode
docker run ... --net=bridge ...
③ Mounting the VF NIC to the Docker Namespace
pid=$(docker inspect -f '{{.State.Pid}}' {docker name})
mkdir -p /var/run/netns
ln -s /proc/${pid}/ns/net /var/run/netns/${pid}
ip link set {VF Name} netns ${pid}
```

#### VF mode of the hinic NIC in the container scenario
```
① Create VF
echo 4 > /sys/class/net/enp5s0/device/sriov_numvfs
② Setting a Fixed MAC Address for a VF
ip link set enp5s0 vf 0 mac 18:3d:5e:bf:6c:22
ip link set enp5s0 vf 1 mac 18:3d:5e:bf:6c:33
You can run the ip link show command to check whether the setting is successful.
③ Creating a Container in Bridge Network Mode
docker run ... --net=bridge ...
④ Mounting the VF NIC to the Docker Namespace
pid=$(docker inspect -f '{{.State.Pid}}' {docker name})
mkdir -p /var/run/netns
ln -s /proc/${pid}/ns/net /var/run/netns/${pid}
ip link set {VF Name} netns ${pid}

Notes：
① In the configuration file lstack.conf of the Gazelle, set mac to the MAC address manually set in step ② and ignore the MAC address displayed in enp5s0v0 queried by running the ip a command.
② In non-container scenarios, if the Gazelle is used and the hinic vf NIC is used, you also need to manually set the MAC address.
```

## Virtual NIC
| Driver | Description | Usage |
|:--|:---|:---|
|e1000|Used to simulate 1 Gbit/s Intel 82545EM NICs. This is the default option for most VMware VMs.|①librte_net_e1000.so is not linked to liblstack.so. In the configuration file, dpdk_args is loaded using -d.<br>②Run the dpdk-devbind -b vfio-pci/igb_uio command to bind the dpdk to the network adapter.|
|e1000e|Simulating a 1 Gbit/s Intel 82574 NIC|①librte_net_e1000e.so is not linked to liblstack.so. In the configuration file, dpdk_args is loaded using -d.<br>②Run the dpdk-devbind -b vfio-pci/igb_uio command to bind the dpdk to the network adapter.|
|vmxnet3|Simulates a 10 Gbit/s NIC for the VMware virtualization platform.|①librte_net_vmxnet3.so is not linked to liblstack.so. dpdk_args in the configuration file is loaded using -d.<br>②Run the dpdk-devbind -b vfio-pci/igb_uio command to bind the dpdk to the network adapter.|

## NIC Upgrade
### NVIDIA Mellanox ConnectX Series NICs
1. Downloading the MLNX_OFED Driver<br>
Download path: https://network.nvidia.com/products/infiniband-drivers/linux/mlnx_ofed/ <br>
Select a proper driver version based on the official note. For example, if CX4 or CX5 is used, select MLNX_OFED 5.8-x.

2. Installation Dependency
```
yum install -y tk make tcsh pciutils-devel lsof gcc kernel-devel
yum install -y python3-devel automake rpm-build autoconf createrepo elfutils-devel lsof libtool
```
3. Upgrade Installation
```
#If rdma-core exists, an error is reported. In this case, you need to uninstall it first.
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
### Other Nics
Not supported.

## Common Problems and Solutions
### 1. In the physical machine or VM scenario, the DPDK is not bound to a NIC. <br>
```
LSTACK: create_control_thread:171 create control_easy_thread success
LSTACK: stack_group_init_mempool:562 config::num_cpu=1 num_process=1
LSTACK: ethdev_port_id:369 No NIC is matched
EAL: Error - exiting with code: 1
  Cause: gazelle_network_init:306 init_dpdk_ethdev failed
```
Solution：<br>
① `ip a` query the MAC address of the NIC and write the MAC address to device in the lstack.conf file.<br>
② Run the `dpdk-devbind -b vfio-pci/igb_uio` command.<br>
③ Run the `dpdk-devbind -s` command to check whether the Network devices using DPDK-compatible driver list is bound successfully.

### 2. In the physical machine, VM, or container scenario, the NIC device and the CPU bound to the Gazelle are not on the same NUMA.<br>
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
Solution:<br>
① Allocate hugepage memory to the node where the NIC resides.
```
echo 1024 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages
```
②Alternatively, change the CPU used by Gazelle to the same NUMA as the NIC. You need to change the values of num_cpus and dpdk_args (hugepage memory allocation) in the lstack.conf file.

### 3. In the container scenario, the CPU used by Gazelle is not within the CPU range used for container startup.<br>
```
EAL: VFIO support initialized
EAL: FATAL: Cannot set affinity
EAL: Cannot set affinity
EAL: Error - exiting with code: 1
  Cause: create_control_thread:164 dpdk_eal_init failed ret=-1 errno=2
```
Soultion:<br>
① Change the value of num_cpus in the lstack.conf file to the CPU used by the container.

### 4. In the container+VF passthrough network mode, the NIC MAC address of the hinic NIC is different from the MAC address in the lstack.conf file.<br>
```
LSTACK: create_control_thread:171 create control_easy_thread success
LSTACK: stack_group_init_mempool:562 config::num_cpu=1 num_process=1
LSTACK: ethdev_port_id:363 nic mac:02:09:c0:f5:05:bc not match
LSTACK: ethdev_port_id:369 No NIC is matched
EAL: Error - exiting with code: 1
  Cause: gazelle_network_init:306 init_dpdk_ethdev failed
```
Solution:<br>
① After creating a VF NIC, you need to configure a fixed MAC address for the VF NIC. For details, see the method of setting up the VF passthrough network for the hinic NIC in the container scenario.

### 5. Failed to bind the DPDK to the NIC device because the vfio driver does not exist in the container or the device directory is not shared.
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
Solution:<br>
① Add the -v /lib/modules/:/lib/modules/ -v /dev:/dev shared path when the container is running.<br>
② Alternatively, stop the container, run the dpdk-devbind -b command to bind the network adapter to the container, and then start the container.


