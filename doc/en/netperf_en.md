# Gazelle supports netperf performance testing

Netperf is a network performance measurement tool used to assess network throughput and latency. It can test the performance of TCP and UDP protocols and offers various test modes and options to meet different testing needs. Gazelle has partially supported netperf testing and continues to adapt and improve.

## Support Overview
### Version Compatibility
lwip-2.1.3-115 or later versions: [lwIP Repository](https://gitee.com/src-openeuler/lwip)  
openeuler/gazelle versions from 2024/02/02 onwards: [Gazelle Repository](https://gitee.com/openeuler/gazelle) (master branch)  
netperf-2.7.0 version: [Netperf Repository](https://gitee.com/src-openeuler/netperf)  

Note: src-openEuler/gazelle is not currently synchronized. The version number supporting netperf functionality will be updated upon synchronization.

### Test Scope
TCP_STREAM: Tests TCP throughput  
TCP_RR: Tests TCP latency  
Note: Currently, TCP bidirectional gazelle + physical machine scenarios only support packet lengths <1436 (MTU)

UDP_STREAM: Tests UDP throughput  
UDP_RR: Tests UDP latency  
Note: Currently, UDP-related tests only support packet lengths <1436 (MTU)

## Usage Instructions
### Environment Setup
1. Follow the gazelle user guide to configure the environment properly, then install netperf via yum or install netperf from source code.
```
Gazelle User Guide: [link](https://gitee.com/openeuler/gazelle/blob/master/doc/user-guide.md)
```
2. Add or modify the configuration item nonblock_mode=0 in /etc/gazelle/lstack.conf.
3. If testing UDP, add or modify the configuration item udp_enable=1 in /etc/gazelle/lstack.conf.

### Testing Commands
1. Server
```
GAZELLE_BIND_PROCNAME=netserver LD_PRELOAD=/usr/lib64/liblstack.so netserver -D -f -4 -L ip1
```
Note: ip1 should be consistent with /etc/gazelle/lstack.conf; -D for running in the foreground; -f for not forking (fork not supported); -4 for IPv4.

2. Client
```
# TCP_STREAM
GAZELLE_BIND_PROCNAME=netperf LD_PRELOAD=/usr/lib64/liblstack.so netperf -H ip1 -L ip2 -t TCP_STREAM -l 10 -- -m 1024
```
Note: ip1 is the server IP; ip2 is the client IP; -t specifies the test type; -l specifies the test duration; -- specifies more configurable parameters; -m specifies the packet length for *_STREAM related test types.

```
# TCP_RR + Latency Test
GAZELLE_BIND_PROCNAME=netperf LD_PRELOAD=/usr/lib64/liblstack.so netperf -H ip1 -L ip2 -t TCP_RR -l 10 -- -r 1024 -O MIN_LATENCY,MAX_LATENCY,MEAN_LATENCY,P99_LATENCY,STDDEV_LATENCY,THROUGHPUT,THROUGHPUT_UNITS
```
Note: -r specifies the packet length for *_RR related test types; -O specifies the test results to display.

```
# UDP_STREAM + Latency Test
GAZELLE_BIND_PROCNAME=netperf LD_PRELOAD=/usr/lib64/liblstack.so netperf -H ip1 -L ip2 -t UDP_STREAM -l 10 -- -m 1024
```
Note: ip1 is the server IP; ip2 is the client IP; -t specifies the test type; -l specifies the test duration; -- specifies more configurable parameters; -m specifies the packet length for *_STREAM related test types.

```
# UDP_RR + Latency Test
GAZELLE_BIND_PROCNAME=netperf LD_PRELOAD=/usr/lib64/liblstack.so netperf -H ip1 -L ip2 -t UDP_RR -l 10 -- -r 1024 -O MIN_LATENCY,MAX_LATENCY,MEAN_LATENCY,P99_LATENCY,STDDEV_LATENCY,THROUGHPUT,THROUGHPUT_UNITS
```
Note: -r specifies the packet length for *_RR related test types; -O specifies the test results to display.

## Usage Example
The following examples are for reference and testing purposes. Actual data may vary due to different testing environments.

### Server
```
[root@openEuler ~]# GAZELLE_BIND_PROCNAME=netserver LD_PRELOAD=/usr/lib64/liblstack.so netserver -D -4 -f -L 192.168.1.36
# Start-up logs omitted
Starting netserver with host '192.168.1.36' port '12865' and family AF_INET
```

### Client
#### TCP_STREAM
```
[root@openEuler lstack]# GAZELLE_BIND_PROCNAME=netperf LD_PRELOAD=/usr/lib64/liblstack.so netperf -H 192.168.1.36 -L 192.168.1.34 -t TCP_STREAM -l 2 -- -m 1024
# Start-up logs omitted
MIGRATED TCP STREAM TEST from 192.168.1.34 () port 0 AF_INET to 192.168.1.36 () port 0 AF_INET
Recv   Send    Send
Socket Socket  Message  Elapsed
Size   Size    Size     Time     Throughput
bytes  bytes   bytes    secs.    10^6bits/sec

131072  16384   1024    2.00     9824.61
```

#### TCP_RR+Latency Test
```
[root@openEuler lstack]# GAZELLE_BIND_PROCNAME=netperf LD_PRELOAD=/usr/lib64/liblstack.so netperf -H 192.168.1.36 -L 192.168.1.34 -t TCP_RR -l 2 -- -r 1024 -O MIN_LATENCY,MAX_LATENCY,MEAN_LATENCY,P99_LATENCY,STDDEV_LATENCY,THROUGHPUT,THROUGHPUT_UNITS
# Start-up logs omitted
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
# Start-up logs omitted
MIGRATED UDP STREAM TEST from 192.168.1.34 () port 0 AF_INET to 192.168.1.36 () port 0 AF_INET
Socket  Message  Elapsed      Messages
Size    Size     Time         Okay Errors   Throughput
bytes   bytes    secs            #      #   10^6bits/sec

212992    1024   5.00       344561      0     564.42
212992           5.00       344533            564.38
```

#### UDP_RR+Latency Test
```
[root@openEuler lstack]# GAZELLE_BIND_PROCNAME=netperf LD_PRELOAD=/usr/lib64/liblstack.so netperf -H 192.168.1.36 -L 192.168.1.34 -t UDP_RR -l 10 -- -r 1024 -O MIN_LATENCY,MAX_LATENCY,MEAN_LATENCY,P99_LATENCY,STDDEV_LATENCY,THROUGHPUT,THROUGHPUT_UNITS
# Start-up logs omitted
MIGRATED UDP REQUEST/RESPONSE TEST from 192.168.1.34 () port 0 AF_INET to 192.168.1.36 () port 0 AF_INET : first burst 0
Minimum      Maximum      Mean         99th         Stddev       Throughput Throughput
Latency      Latency      Latency      Percentile   Latency                 Units
Microseconds Microseconds Microseconds Latency      Microseconds
                                       Microseconds
77           7293         176.77       885          193.87       5646.59    Trans/s
```

## Common Issues and Solutions
### Common Issue 1
After starting the client, the server exits, and the client reports the following error:
```
Resource temporarily unavailable
netperf: remote error 11
```
Reason: nonblock_mode=0 is not configured in /etc/gazelle/lstack.conf.

### Common Issue 2
After testing TCP, encountering errors or abnormal data when testing UDP.
Reason: udp_enable=1 is not configured in /etc/gazelle/lstack.conf.
