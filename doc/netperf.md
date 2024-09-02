# Gazelle支持netperf性能测试
Netperf是一个网络性能测量工具，用于评估网络传输速度和延迟。它可以测试TCP和UDP协议的性能，并提供了多种测试模式和选项，以满足不同的测试需求。
gazelle已部分支持netperf测试，并持续适配及改进。

## 支持情况说明
### 版本配套
lwip-2.1.3-115或之后版本：https://gitee.com/src-openeuler/lwip  
openeuler/gazelle 2024/02/02及之后版本：https://gitee.com/openeuler/gazelle master分支   
netperf-2.7.0版本：https://gitee.com/src-openeuler/netperf  

注：src-openEuler/gazelle暂未同步，同步后在此刷新支持netperf功能的版本号。  

### 测试范围
TCP_STREAM，测试tcp吞吐量  
TCP_RR，测试tcp时延  

UDP_STREAM，测试udp吞吐量  
UDP_RR，测试udp时延  

## 使用说明
### 环境配置
1、按照gazelle用户指南配置好环境后，yum install netperf或者通过源码安装netperf；
```
gazelle用户指南：https://gitee.com/openeuler/gazelle/blob/master/doc/user-guide.md
```
2、在/etc/gazelle/lstack.conf中，添加或修改配置项nonblock_mode=0；  
3、如果测试udp，需要在/etc/gazelle/lstack.conf中，添加或修改配置项udp_enable=1。  

### 测试命令
1、server
```
GAZELLE_BIND_PROCNAME=netserver LD_PRELOAD=/usr/lib64/liblstack.so netserver -D -f -4 -L ip1
```
注：ip1与/etc/gazelle/lstack.conf一致；-D为取消后台运行；-f为取消执行fork，不支持fork；-4为ipv4

2、client
```
#TCP_STREAM
GAZELLE_BIND_PROCNAME=netperf LD_PRELOAD=/usr/lib64/liblstack.so netperf -H ip1 -L ip2 -t TCP_STREAM -l 10 -- -m 1024
```
注：ip1为server ip；ip2为client ip；-t为指定测试类型；-l为指定测试时长；--为指定更多可配置参数；-m为*_STREAM相关测试类型指定包长

```
#TCP_RR + 时延测试
GAZELLE_BIND_PROCNAME=netperf LD_PRELOAD=/usr/lib64/liblstack.so netperf -H ip1 -L ip2 -t TCP_RR -l 10 -- -r 1024 -O MIN_LATENCY,MAX_LATENCY,MEAN_LATENCY,P99_LATENCY,STDDEV_LATENCY,THROUGHPUT,THROUGHPUT_UNITS
```
注：-r为*_RR相关测试类型指定包长；-O为指定需要show的测试结果

```
#UDP_STREAM+ 时延测试
GAZELLE_BIND_PROCNAME=netperf LD_PRELOAD=/usr/lib64/liblstack.so netperf -H ip1 -L ip2 -t UDP_STREAM -l 10 -- -m 1024
```
注：ip1为server ip；ip2为client ip；-t为指定测试类型；-l为指定测试时长；--为指定更多可配置参数；-m为*_STREAM相关测试类型指定包长

```
#UDP_RR + 时延测试
GAZELLE_BIND_PROCNAME=netperf LD_PRELOAD=/usr/lib64/liblstack.so netperf -H ip1 -L ip2 -t UDP_RR -l 10 -- -r 1024 -O MIN_LATENCY,MAX_LATENCY,MEAN_LATENCY,P99_LATENCY,STDDEV_LATENCY,THROUGHPUT,THROUGHPUT_UNITS
```
注：-r为*_RR相关测试类型指定包长；-O为指定需要show的测试结果

## 使用示例
以下示例因测试环境不同数据差异较大，仅供参考测试方法。
### server
```
[root@openEuler ~]# GAZELLE_BIND_PROCNAME=netserver LD_PRELOAD=/usr/lib64/liblstack.so netserver -D -4 -f -L 192.168.1.36
#省略启动日志
Starting netserver with host '192.168.1.36' port '12865' and family AF_INET
```

### client
#### TCP_STREAM
```
[root@openEuler lstack]# GAZELLE_BIND_PROCNAME=netperf LD_PRELOAD=/usr/lib64/liblstack.so netperf -H 192.168.1.36 -L 192.168.1.34 -t TCP_STREAM -l 2 -- -m 1024
#省略启动日志
MIGRATED TCP STREAM TEST from 192.168.1.34 () port 0 AF_INET to 192.168.1.36 () port 0 AF_INET
Recv   Send    Send
Socket Socket  Message  Elapsed
Size   Size    Size     Time     Throughput
bytes  bytes   bytes    secs.    10^6bits/sec

131072  16384   1024    2.00     9824.61
```

#### TCP_RR+时延测试
```
[root@openEuler lstack]# GAZELLE_BIND_PROCNAME=netperf LD_PRELOAD=/usr/lib64/liblstack.so netperf -H 192.168.1.36 -L 192.168.1.34 -t TCP_RR -l 2 -- -r 1024 -O MIN_LATENCY,MAX_LATENCY,MEAN_LATENCY,P99_LATENCY,STDDEV_LATENCY,THROUGHPUT,THROUGHPUT_UNITS
#省略启动日志
MIGRATED TCP REQUEST/RESPONSE TEST from 192.168.1.34 () port 0 AF_INET to 192.168.1.36 () port 0 AF_INET : first burst 0
Minimum      Maximum      Mean         99th         Stddev       Throughput Throughput
Latency      Latency      Latency      Percentile   Latency                 Units
Microseconds Microseconds Microseconds Latency      Microseconds
                                       Microseconds
4            227          8.94         28           1.68         60085.02   Trans/s

```

#### UDP_STREAM
```
[root@openEuler lstack]# GAZELLE_BIND_PROCNAME=netperf LD_PRELOAD=/usr/lib64/liblstack.so netperf -H 192.168.1.36 -L 192.168.1.34 -t UDP_STREAM -l 5 -- -m 1024
#省略启动日志
MIGRATED UDP STREAM TEST from 192.168.1.34 () port 0 AF_INET to 192.168.1.36 () port 0 AF_INET
Socket  Message  Elapsed      Messages
Size    Size     Time         Okay Errors   Throughput
bytes   bytes    secs            #      #   10^6bits/sec

212992    1024   5.00       344561      0     564.42
212992           5.00       344533            564.38

```

#### UDP_RR+时延测试
```
[root@openEuler lstack]# GAZELLE_BIND_PROCNAME=netperf LD_PRELOAD=/usr/lib64/liblstack.so netperf -H 192.168.1.36 -L 192.168.1.34 -t UDP_RR -l 10 -- -r 1024 -O MIN_LATENCY,MAX_LATENCY,MEAN_LATENCY,P99_LATENCY,STDDEV_LATENCY,THROUGHPUT,THROUGHPUT_UNITS
#省略启动日志
MIGRATED UDP REQUEST/RESPONSE TEST from 192.168.1.34 () port 0 AF_INET to 192.168.1.36 () port 0 AF_INET : first burst 0
Minimum      Maximum      Mean         99th         Stddev       Throughput Throughput
Latency      Latency      Latency      Percentile   Latency                 Units
Microseconds Microseconds Microseconds Latency      Microseconds
                                       Microseconds
77           7293         176.77       885          193.87       5646.59    Trans/s

```

## 常见问题及解决方案
### 常见问题1
启动client后，sever退出，client报错如下
```
Resource temporarily unavailable
netperf: remote error 11
```
原因：/etc/gazelle/lstack.conf中没有配置nonblock_mode=0

### 常见问题2
测试TCP后，想要测试UDP出现错误或者数据异常  
原因：/etc/gazelle/lstack.conf中没有配置udp_enable=1  
