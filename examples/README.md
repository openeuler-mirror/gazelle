# Gazelle demo程序说明

## 功能

* 支持 TCP 、UDP、 unix 非阻塞通讯。
* 支持多线程网络 IO 复用模型，线程之间相互独立。TCP 的 `listen` 、`epoll` 、`read` 、`write` 、`connect` 等接口都在同一线程内。`connect` 连接数可配。
* 支持多线程网络非对称模型，一个 listen 线程，若干个读写线程。listen 线程和读写线程使用 `poll` / `epoll` 监听事件。
* 支持 `recvmsg` 、`sendmsg` 、`recv` 、`send` 、`recvfrom`、`sendto`、`getpeername` 、`getsockopt` 、`epoll_ctl` 等 posix 接口。
* 网络通讯报文采用问答方式，丢包或者内容错误则报错并停止通讯。报文内容有变化，长度可配。

## 网络模型

* **单线程非阻塞**：采用同步非阻塞 IO 模型，在单线程中采用非阻塞的方式监听并发起 IO 请求，当内核中数据到达后读取数据、执行业务逻辑并发送。

```
                            单线程非阻塞模型
                                  |
                            创建套接字并监听
                                  | <-------+
                               读取数据      |
                                  |         |
                               业务逻辑      |
                                  |         |
                               发送数据      |
                                  |         |
                                  +---------+
```

* **多线程非阻塞IO复用**：基于 `epoll` 实现多线程非阻塞 IO 模型。每个线程之间互不干涉。通过 `epoll` 监控多个当前线程负责的 fd ，当任何一个数据状态准备就绪时，返回并执行读写操作和对应的业务逻辑。

```
                            多线程非阻塞IO复用模型
                                    |
                               创建套接字并监听
                                    |
                                创建若干个线程
                                    |
          +------------+------------+------------+------------+
          |            |            |            |            |
   创建套接字并监听      ...          ...     创建套接字并监听     ...
          |                                      |
    线程内部初始化                             线程内部初始化
    epoll，并注册                             epoll，并注册
    套接字监听事件                             套接字监听事件
          | <---------+                           | <----------+
    +-----+-----+     |                     +-----+-----+      |
    |           |     |                     |           |      |
  (新连接)    (新报文)  |                   (新连接)    (新报文)   |
  建连并注     读取数据  |                   建连并注     读取数据  |
  册新连接     业务逻辑  |                   册新连接     业务逻辑  |
  监听事件     发送数据  |                   监听事件     发送数据  |
    |           |     |                      |           |     |
    +-----+-----+     |                      +-----+-----+     |
          |           |                            |           |
          +-----------+                            +-----------+
```

* **多线程非阻塞非对称**：采用基于 `epoll` 的单线程多路 IO 复用监听连接事件，并采用多线程的方式完成后续读写监听业务。 server 在启动监听之前，开辟一定数量的线程，用线程池管理。主线程创建监听 `fd` 之后，采用多路 IO 复用机制 (`epoll`) 进行 IO 状态监控。当监听到客户端的连接请求时，建立连接并将相关 `fd` 分发给线程池的某个线程进行监听。线程池中的每个线程都采用多路 IO 复用机制 (`epoll`) ，用来监听主线程中建立成功并分发下来的 `socket` 。

```
        多线程非阻塞非对称模型       +------------------------+
                |                |                        |
            创建监听线程           |          +-------------+---  ... -----+
                |                |          |             |              |
          创建套接字，初始化        |      初始化epoll       ...    ... 初始化epoll
          eopll并且并注册套        |      并注册事件                    并注册事件
          接字监听事件             |          | <-- +                      | <-- +
                |                |       读取数据  |                    读取数据  |
        当有新连接时，创建工作线程   ｜       业务逻辑  |                    业务逻辑  |
                |                |       发送数据  |                    发送数据  |
                +----------------+          |     |                      |     |
                                            +-----+                      +-----+
```

* **客户端**：创建若干线程，每个线程创建若干 `socket` 与客户端建立连接，并使用 `epoll` 进行状态监控，建连后向服务端发送数据并等待服务端数据传回，当接受到服务端传回数据后进行校验，校验无误再次发送数据。

```
                            多线程非阻塞IO复用模型
                                    |
                                创建若干个线程
          +------------+------------+------------+------------+
          |            |            |            |            |
    线程内部初始化                             线程内部初始化
    epoll             ...           ...      epoll           ...
          |                                      |
     依次创建套接字,                          依次创建套接字,
     建连并注册事件                           建连并注册事件
          | <---------+                           | <---------+
       发送数据        |                         发送数据        |
     接收数据并校验     |                       接收数据并校验     |
          |           |                           |           |
    +------------+    |                     +------------+    |
    |            |    |                     |            |    |
   成功          失败  |                    成功          失败   |
    |            |    |                     |            |    |
  发送数据        终止  |                   发送数据        终止  |
    |                 |                     |                 |
    +-----------------+                     +-----------------+
```

## 程序接口

* `-a, --as [server | client]`：作为服务端还是客户端。
  * `server`：作为服务端。
  * `client`：作为客户端。
* `-i, --ip [xxx.xxx.xxx.xxx]`：IP地址。
* `-g, --groupip [xxx.xxx.xxx.xxx]`：UDP组播地址。
* `-p, --port [xxxx]`：端口。
* `-m, --model [mum | mud]`：采用的网络模型类型。
  * `mum (multi thread, unblock, multiplexing IO)`：多线程非阻塞IO复用。
  * `mud (multi thread, unblock, dissymmetric)`：多线程非阻塞非对称。
* `-t, --threadnum`：线程数设置。
* `-c, --connectnum`：连接数设置。当 `domain` 设置为 `udp` 时，`connectnum` 会被设置为1。
* `-D, --domain [unix | tcp | udp]`：通信协议。
  * `unix`：基于 unix 协议实现。
  * `tcp`：基于 tcp 协议实现。
  * `udp`：基于 udp 协议实现。
* `-A, --api [readwrite | recvsend | recvsendmsg | readvwritev | recvfromsendto | recvfrom]`：内部实现的接口类型。
  * `readwrite` ：使用 `read` 和 `write` 接口。
  * `recvsend` ：使用 `recv` 和 `send` 接口。
  * `recvsendmsg` ：使用 `recvmsg` 和 `sendmsg` 接口。
  * `recvfromsendto`：使用 `recvfrom` 和 `sendto` 接口。
  * `recvfrom`：仅使用 `recvfrom` 接口，用于udp组播的多服务端模型。
* `-P, --pktlen [xxxx]`：报文长度配置。
* `-v, --verify`：是否校验报文。
* `-r, --ringpmd`：是否基于dpdk ring PMD 收发环回。
* `-d, --debug`：是否打印调试信息。
* `-h, --help`：获得帮助信息。
* `-E, --epollcreate`：epoll_create方式。
  * `ec`：使用epoll_create(int size)生成epoll专用的文件描述符。
  * `ec1`：使用epoll_create1(int flags)生成epoll专用的文件描述符,flags = EPOLL_CLOEXEC。
* `-C, --accept`：accept的方式。
  * `ac`：使用accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)通过套接口接受连接。
  * `ac4`：使用accept4(int sockfd, struct sockaddr *addr,socklen_t *addrlen, int flags)通过套接口接受连接,flags=SOCK_CLOEXEC。
* `-k, --keep_alive`：配置TCP keep_alive idle 时间(second)。

## 使用

 * **环境配置**
   * 参考 https://gitee.com/openeuler/libboundscheck 。

 * **编译**

```
cd build
mkdir examples
cd examples
cmake ../../examples
make
```

 * **查看帮助信息**

 ```
 ./examples --help

 -a, --as [server | client]: set programas server or client. 
    server: as server. 
    client: as client. 
-i, --ip [???.???.???.???]: set ip address. 
-p, --port [????]: set port number in range of 1024 - 65535. 
-m, --model [mum | mud]: set the network model. 
    mum: multi thread, unblock, multiplexing IO network model. 
    mud: multi thread, unblock, dissymmetric network model. 
-t, --threadnum [???]: set thread number in range of 1 - 1000. 
-c, --connectnum [???]: set connection number of each thread. 
-D, --domain [unix | posix]: set domain type is server or client. 
    unix: use unix's api. 
    tcp: use tcp api. 
    udp: use udp api.
-A, --api [readwrite | recvsend | recvsendmsg | recvfromsendto | recvfrom]: set api type is server or client. 
    readwrite: use `read` and `write`. 
    recvsend: use `recv and `send`. 
    recvsendmsg: use `recvmsg` and `sendmsg`. 
    recvfromsendto: use `recvfrom` and `sendto`.
    recvfrom: just use `recvfrom`, used by the server to receive group messages.
-P, --pktlen [????]: set packet length in range of 2 - 10485760. 
-v, --verify: set to verifying the message packet. 
-r, --ringpmd: set to use ringpmd. 
-d, --debug: set to print the debug information. 
-h, --help: see helps.
-E, --epollcreate: epoll_create method.
    ec: use epoll_create(int size) to create epoll fd.
    ec1:use epoll_create(int flags) to create epoll fd, flags=EPOLL_CLOEXEC.
-C, --accept: accept method.
    ac: use accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) to accept a connection on a socket
    ac4: use accept4(int sockfd, struct sockaddr *addr,socklen_t *addrlen, int flags) to accept a connection on a socket, flags=SOCK_CLOEXEC.
 ```

 * 创建tcp服务端

```
./example --as server --verify

[program parameters]: 
--> [as]:                       server 
--> [server ip]:                127.0.0.1 
--> [server port]:              5050 
--> [model]:                    mum 
--> [thread number]:            1 
--> [domain]:                   tcp 
--> [api]:                      read & write 
--> [packet length]:            1024 
--> [verify]:                   on 
--> [ringpmd]:                  off 
--> [debug]:                    off 
--> [epoll create]:             ec
--> [accept]:                   ac

[program informations]: 
--> <server>: [connect num]: 0, [receive]: 0.000 B/s
```

 * 创建tcp客户端

```
./example --as client --verify

[program parameters]: 
--> [as]:                       client 
--> [server ip]:                127.0.0.1 
--> [server port]:              5050 
--> [thread number]:            1 
--> [connection number]:        1 
--> [domain]:                   tcp 
--> [api]:                      read & write 
--> [packet length]:            1024 
--> [verify]:                   on 
--> [ringpmd]:                  off 
--> [epoll create]:             ec
--> [accept]:                   ac

[program informations]: 
--> <client>: [connect num]: 80, [send]: 357.959 MB/s
```

 * 创建udp组播服务端

```
./example -A server -D udp -i 192.168.0.1 -g 225.0.0.1 -A recvfromsendto

[program parameters]: 
--> [as]:                       server 
--> [server ip]:                192.168.0.1
--> [server group ip]:          225.0.0.1
--> [server port]:              5050 
--> [model]:                    mum 
--> [thread number]:            1 
--> [domain]:                   udp 
--> [api]:                      recvfrom & sendto 
--> [packet length]:            1024 
--> [verify]:                   on 
--> [ringpmd]:                  off 
--> [debug]:                    off 
--> [epoll create]:             ec
--> [accept]:                   ac

[program informations]: 
--> <server>: [connect num]: 0, [receive]: 0.000 B/s
```

 * 创建udp组播客户端

```
./example -A client -D udp -i 192.168.0.1 -g 225.0.0.1 -A recvfromsendto

[program parameters]: 
--> [as]:                       server 
--> [server ip]:                225.0.0.1
--> [client send ip]:           192.168.0.1
--> [server port]:              5050 
--> [thread number]:            1
--> [connection number]:        1 
--> [domain]:                   udp 
--> [api]:                      recvfrom & sendto 
--> [packet length]:            1024 
--> [verify]:                   on 
--> [ringpmd]:                  off 
--> [epoll create]:             ec
--> [accept]:                   ac

[program informations]: 
--> <client>: [connect num]: 0, [send]: 0.000 B/s
```
