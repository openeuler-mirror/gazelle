# Introduction to Virtio User
virtio-user in kernel space are an alternative to DPDK KNI for transferring packets between a DPDK packet processing application and the kernel stack.When this feature is enabled, messages that Gazelle currently does not support processing will be passed to the kernel protocol stack for processing.

## Host pattern

### Host computer

1. Install dpdk and configure Huge page memory
<span id="target-anchor"></span>

```shell
yum install -y dpdk
```

```shell
echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
mkdir -p /mnt/hugepages-lstack
chmod -R 700 /mnt/hugepages-lstack
mount -t hugetlbfs nodev /mnt/hugepages-lstack
```

Reference: [Gazelle User Guide - Mount huge pages](https://gitee.com/openeuler/gazelle/blob/master/doc/user-guide_en.md#3-huge-page-memory-configuration)

1. Bind the network card to dpdk

Taking the example of binding the network card to igb_uio

```shell
cd /lib/modules
my_var=$(find /lib/modules/ -name igb_uio.ko)
modprobe uio
#Load ko
insmod ${my_var}

#Using igc_io
dpdk-devbind -b igb_uio enp3s0
```


Reference: [Gazelle User Guide-- Bind the network card to dpdk](https://gitee.com/openeuler/gazelle/blob/master/doc/user-guide.md#2-dpdk%E7%BB%91%E5%AE%9A%E7%BD%91%E5%8D%A1)

3. Install docker

```shell
yum install -y docker
```

4. Import image

[Container image download](https://mirrors.tools.huawei.com/home)

```shell
docker load -i openEuler-docker.x86_64.tar.xz
```


5. Start container
```shell
docker run -d -it --privileged -v /lib/modules:/lib/modules -v /mnt:/mnt -v /dev:/dev -v /sys/bus/pci/drivers:/sys/bus/pci/drivers -v /sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages -v /sys/devices/system/node:/sys/devices/system/node -v /dev:/dev openeuler-22.03-lts-sp2 bash
```

```shell
Docker Startup Mapping File Explanation
-v /lib/modules             : Mapping kernel modules to/lib/modules
-v /mnt:/mnt                : maps external storage devices, file systems
-v /dev:/dev                : maps kernel devices
-v /sys/bus/pci/drivers:/sys/bus/pci/drivers             : Mapping driver files
-v /sys/kernel/mm/pages:/sys/kernel/mm/pages             : maps large page information
-v /sys/devices/system/node:/sys/devices/system/node     : maps node information
```

6. Enter the container

```shll
docker exec -it xxxxx bash
```

###  In container
1. install dpdk and gazelle


```shll
yum install -y dpdk gazele
```

2. modify config file

```shell
flow_bifurcation=1 # switch on
host_addr="192.168.1.152"
mask_addr="255.255.255.0"
gateway_addr="192.168.1.1"
devices="52:54:00:de:2a:57" # Change the MAC address to the network card address bound to DPDK
```
3. start gazelle
Taking Redis acceleration as an example

```shell
LD_PRELOAD=/usr/lib64/liblstack.so GAZELLE_BIND_PROCNAME=redis-server /root/redis-server /root/redis.conf
```


### Supported commands
+ ifconfig

+ tcpdump

+ ssh -- SSH services needs to be enabled. If it is not enabled, you can use the following method to enable it
    <span id="startsshconfig"></span>
    ```shell
    [root@eb2936ebeaaf ~]# yum install openssh-server
    [root@eb2936ebeaaf ~]# vim /etc/ssh/sshd_config
	Port 22
	PubkeyAuthentication yes 
    [root@eb2936ebeaaf ~]# /usr/sbin/sshd   
    [root@eb2936ebeaaf ~]# netstat -pant | grep sshd 
    
    ```

## VF-pattern
### Host computer
1. Install dpdk and configure Huge page memory

    Reference:[hsot pattern-Install dpdk and configure Huge page memory](#target-anchor)

3. Install Docker and import image
```shell
yum install -y docker
docker load -i openEuler-docker.x86_64.tar.xz
```


3. Start container
```shell
docker run -d -it --network host --privileged -v /lib/modules:/lib/modules -v \
/mnt:/mnt -v /dev:/dev -v /sys/bus/pci/drivers:/sys/bus/pci/drivers -v \
/sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages -v \
/sys/devices/system/node:/sys/devices/system/node -v /dev:/dev  \
openeuler-22.03-lts-sp4 bash
```

4. Configure VF direct network card

```shell
echo 2 > /sys/class/net/enp130s0f1/device/sriov_numvfs 
docker ps
PID = docker inspect -f '{{.State.Pid}}' Container_name
mkdir -p /var/run/netns
ln -s /proc/PID/ns/net /var/run/netns/PID
ip link set enp129s0f1v0 netns PID
```
5. Enter the container
```shell
docker exec -it xxx bash
```


### In container
1. install dpdk, gazelle

```shell
yum install -y dpdk gazele
```

2. modify config file
```shell
flow_bifurcation=1 

host_addr="124.88.28.219"
mask_addr="255.255.0.0"
gateway_addr="124.88.0.1"
devices="ae:5c:b7:ab:89:09"   
```

3. start gazelle
Taking Redis acceleration as an example
```shell
LD_PRELOAD=/usr/lib64/liblstack.so GAZELLE_BIND_PROCNAME=redis-server /root/redis-server /root/redis.conf
```
### Supported commands
+ ifconfig
+ tcpdump
+ ssh -- SSH login needs to be enabled. If it is not enabled, please refer to [host_pattern: Supported operation and maintenance commands](#startsshconfig)
