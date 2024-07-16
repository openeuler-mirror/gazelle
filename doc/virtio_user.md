# virtio_user 简介
virtio_user 是一种DPDK kni的替代方案，用于在DPDK数据包处理程序和内核协议栈之间传递报文。当开启此功能后，对于gazelle当前不支持处理的报文，将传递到内核协议栈进行处理。


## host模式

### 宿主机

1. 安装dpdk，配置大页
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

参考：[Gazelle用户指南--大页内存配置-- 挂载大页内存](https://gitee.com/openeuler/gazelle/blob/master/doc/user-guide.md#3-%E5%A4%A7%E9%A1%B5%E5%86%85%E5%AD%98%E9%85%8D%E7%BD%AE)

2. dpdk 绑定网卡

以网卡绑定 igb_uio 为例

```shell
cd /lib/modules
my_var=$(find /lib/modules/ -name igb_uio.ko)
modprobe uio
# 加载ko
insmod ${my_var}

#使用igb_uio
dpdk-devbind -b igb_uio enp3s0
```


参考: [Gazelle用户指南--dpdk绑定网卡](https://gitee.com/openeuler/gazelle/blob/master/doc/user-guide.md#2-dpdk%E7%BB%91%E5%AE%9A%E7%BD%91%E5%8D%A1)

3. 安装 docker

```shell
yum install -y docker
```

4. 导入镜像

[容器镜像下载](https://mirrors.tools.huawei.com/home)

```shell
docker load -i openEuler-docker.x86_64.tar.xz
```


5. 启动容器
```shell
docker run -d -it --privileged -v /lib/modules:/lib/modules -v /mnt:/mnt -v /dev:/dev -v /sys/bus/pci/drivers:/sys/bus/pci/drivers -v /sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages -v /sys/devices/system/node:/sys/devices/system/node -v /dev:/dev openeuler-22.03-lts-sp2 bash
```

```shell
docker 启动映射文件解释
-v /lib/modules:/lib/modules 映射内核模块
-v /mnt:/mnt 映射外部存储设备,文件系统
-v /dev:/dev 映射内核设备
-v /sys/bus/pci/drivers:/sys/bus/pci/drivers 映射驱动文件
-v /sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages 映射大页信息
-v /sys/devices/system/node:/sys/devices/system/node 映射节点信息
```

6. 进入容器

```shll
docker exec -it xxxxx bash
```

### 容器内
1. 安装dpdk, gazelle


```shll
yum install -y dpdk gazele
```

2. 修改配置文件

```shell
flow_bifurcation=1 # 打开分流开关
host_addr="192.168.1.152"
mask_addr="255.255.255.0"
gateway_addr="192.168.1.1"
devices="52:54:00:de:2a:57" # 修改mac地址为 dpdk绑定的网卡地址
```
3. 启动gazelle
以加速 redis 为例

```shell
LD_PRELOAD=/usr/lib64/liblstack.so GAZELLE_BIND_PROCNAME=redis-server /root/redis-server /root/redis.conf
```


### 已支持运维命令
+ ifconfig

+ tcpdump

+ ssh -- 需开启ssh 登录，若未开启可按照下面方式开启
    <span id="startsshconfig"></span>
    ```shell
    [root@eb2936ebeaaf ~]# yum install openssh-server
    [root@eb2936ebeaaf ~]# vim /etc/ssh/sshd_config
	Port 22 # 开启端口
	PubkeyAuthentication yes # 修改登录验证方式
    [root@eb2936ebeaaf ~]# /usr/sbin/sshd   # 启动ssh服务
    [root@eb2936ebeaaf ~]# netstat -pant | grep sshd # 查询 ssh 服务是否开启
    
    ```

## VF-直通模式
### 宿主机
1. 安装dpdk，配置大页

    参考[hsot模式-安装dpdk，配置大页](#target-anchor)

3. 安装docker 导入镜像
```shell
yum install -y docker
docker load -i openEuler-docker.x86_64.tar.xz
```


3. 启动容器
```shell
docker run -d -it --network host --privileged -v /lib/modules:/lib/modules -v \
/mnt:/mnt -v /dev:/dev -v /sys/bus/pci/drivers:/sys/bus/pci/drivers -v \
/sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages -v \
/sys/devices/system/node:/sys/devices/system/node -v /dev:/dev  \
openeuler-22.03-lts-sp4 bash
```

4. 配置VF 直通网卡

```shell
echo 2 > /sys/class/net/enp130s0f1/device/sriov_numvfs #创建2个vf，切换用户态和内核态vf网卡的mac地址会变化，建议使用mlx网卡
docker ps
PID = docker inspect -f '{{.State.Pid}}' 容器名称
mkdir -p /var/run/netns
ln -s /proc/PID/ns/net /var/run/netns/PID
ip link set enp129s0f1v0 netns PID
```
5. 进入容器
```shell
docker exec -it xxx bash
```


### 容器内
1. 安装dpdk gazelle

```shell
yum install -y dpdk gazele
```

2. 安装gazelle 修改配置文件
```shell
 
flow_bifurcation=1 # 打开分流开关

host_addr="124.88.28.219"
mask_addr="255.255.0.0"
gateway_addr="124.88.0.1"
devices="ae:5c:b7:ab:89:09"   # 修改MAC 地址为 VF 直通网卡的MAC 地址
```

3. 启动gazelle
以加速 redis 为例
```shell
LD_PRELOAD=/usr/lib64/liblstack.so GAZELLE_BIND_PROCNAME=redis-server /root/redis-server /root/redis.conf
```
### 已支持运维命令
+ ifconfig
+ tcpdump
+ ssh -- 需开启ssh 登录，若未开启可参考[host模式开启ssh](#startsshconfig)
