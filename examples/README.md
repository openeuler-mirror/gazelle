# gazzle 示例程序

* 支持 TCP 、 unix 非阻塞通讯。
* 支持多线程网络 IO 复用模型，线程之间相互独立。TCP 的 `listen` 、`epoll` 、`read` 、`write` 、`connect` 等接口都在同一线程内。`connect` 连接数可配。
* 支持多线程网络非对称模型，一个 listen 线程，若干个读写线程。listen 线程和读写线程使用 `poll` / `epoll` 监听事件。
* 支持 `recvmsg` 、`sendmsg` 、`recv` 、`send` 、`getpeername` 、`getsockopt` 、`epoll_ctl` 等 posix 接口。
* 网络通讯报文采用问答方式，丢包或者内容错误则报错并停止通讯。报文内容有变化，长度可配。

## 网络模型

* **单线程非阻塞**：采用同步非阻塞 IO 模型，在单线程中采用非阻塞的方式监听并发起 IO 请求，当内核中数据到达后读取数据、执行业务逻辑并发送。
* **多线程非阻塞IO复用**：基于 `epoll` 实现多线程非阻塞 IO 模型。每个线程之间互不干涉。通过 `epoll` 监控多个当前线程负责的 fd ，当任何一个数据状态准备就绪时，返回并执行读写操作和对应的业务逻辑。
* **多线程非阻塞非对称**：采用基于 `epoll` 的单线程多路 IO 复用监听连接事件，并采用多线程的方式完成后续读写监听业务。 server 在启动监听之前，开辟一定数量的线程，用线程池管理。主线程创建监听 `fd` 之后，采用多路 IO 复用机制 (`epoll`) 进行 IO 状态监控。当监听到客户端的连接请求时，建立连接并将相关 `fd` 分发给线程池的某个线程进行监听。线程池中的每个线程都采用多路 IO 复用机制 (`epoll`) ，用来监听主线程中建立成功并分发下来的 `socket` 。

## 程序接口

* `-a, --as [server | client]`：作为服务端还是客户端。
  * `server`：作为服务端。
  * `client`：作为客户端。
* `-i, --ip [xxx.xxx.xxx.xxx]`：IP地址。
* `-p, --port [xxxx]`：端口。
* `-m, --model [mum | mud]`：采用的网络模型类型。
  * `mum (multi thread, unblock, multiplexing IO)`：多线程非阻塞IO复用。
  * `mud (multi thread, unblock, dissymmetric)`：多线程非阻塞非对称。
* `-t, --threadnum`：线程数设置。
* `-c, --connectnum`：连接数设置。
* `-A, --api [unix | posix]`：内部实现的接口类型。
  * `unix`：基于 unix 接口实现。
  * `posix`：基于 posix 接口实现。
* `-P, --pktlen [xxxx]`：报文长度配置。
* `-v, --verify`：是否校验报文。
* `-r, --ringpmd`：是否基于dpdk ring PMD 收发环回。
* `-h, --help`：获得帮助信息。

## 使用

```
cd build
mkdir examples
cd examples
cmake ../../examples
make
./examples --help
```
