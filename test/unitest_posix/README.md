### 1.运行方法

首先启动gazelle环境，dpdk接管网卡后，到My_test目录下依次执行下面的命令

注意：运行gazelle的时候。**设置lstack.conf 大页内存的时候最好是1024**，太大会导致gazelle启动的时候会申请很多的文件描述，在测试异步相关接口的时候，文件描述符会超过FD_SETSIZE（1024）导致测试失败。

```bash
mkdir build
cmake ..
make
#执行测试脚本
./main
```

测试完成之后终端会有测试结果，同时会生成log目录，socket_test.log有更详细的日志内容可以查看，每次执行测试程序日志内容都会覆盖

### 2.查看测试覆盖率 

1.cmake启用选项CODE_COVERAGE：进入到build目录下随后执行`cmake -CODE_COVERAGE=ON ..` 

2.make编译 随后先执行一遍main程序`./main`

4.到gazelle的根目录执行命令

```bash
lcov -c -d ./ -o app.info
#生成html
genhtml app.info -o cc_result
```

5.在生成的`cc`目录中即可查看覆盖率结果的html相关文件

### 3.原理介绍

#### 3.1测试方案及框架

​	为Gazelle项目构建一个基于CUnit的单元测试框架，能够在本地及持续集成环境中自动运行，并覆盖项目的主要功能模块，确保关键功能的稳定性。集成代码覆盖率工具，以评估测试的全面性。整个测试的目录结构如下：

```
├── CMakeLists.txt				#测试框架的cmake
├── include
│   └── test_frame.h			#主要头文件
├── main.c						#测试函数main
├──log							#存放测试日志
│   └── test.log
├── POSIX
│   ├── rtw_accept_Test			#不同的测试模块
│   │   ├── CMakeLists.txt		#不同测试模块的cmake
│   │   └── rtw_accept_test.c	#不同测试模块的主要逻辑
│   ├── rtw_bind_Test
│   │   ├── CMakeLists.txt
│   │   └── rtw_bind_test.c
│   ├── rtw_connect_Test
│   │   ├── CMakeLists.txt
│   │   └── rtw_connect_test.c
... ...
└── REAMME.md
```

​	每个模块`(rtw_moudle_Test)`都有对应的测试文件，测试文件根据功能分组，方便管理，测试函数采用统一的格式，例如`test_socket_success`、`test_broadcast_listen_success`，便于识别和维护。使用`CUnit`管理测试套件和测试用例，提供详细的报告输出。测试执行通过`CMakeLists.txt`配置或集成至持续集成工具中。

​	`test_frame.h`里面主要包含了一些宏定义的声明，以及在子目录中测试函数的名称，除此外还包含了一些gazelle和系统的头文件，这样在不同模块测试的时候只需要包含此头文件即可，不需要包含大批相似的头文件，一定程度上促进了代码的简洁性。对于部分接口测试需要其它的头文件，可以单独添加。

​	在CMake中配置`-CODE_COVERAGE=ON`选项（可选），用于测试代码的覆盖率，利用lcov工具计算代码覆盖率。配置日志输出文件，将关键的测试逻辑结果记录到日志当中，方便后期进行维护和bug定位

##### 3.1.1 CMAKE逻辑

1. cmake在一开始设置了可选选项`CODE_COVERAGE`，用于添加`-fprofile-arcs -ftest-coverage`标志，默认是关闭的，可以通过`-DCODE_COVERAGE=ON`开启。随后设置相关编译标志，参考了gazelle源码中的`gazelle/src/lstack/Makefile`的编译设置

2. 设置dpdk相关库为`LIBRTE_LIB`，gazelle的源码打包成库为stack，随后将stack与其它第三方库进行链接，将链接后的stack库作为测试框架运行的基础库

3. 添加可执行程序main，将其与stack与不同的单元测试库链接起来，随后执行main即可运行单元测试

##### 3.1.2 log目录下的日志

​	在测试运行之后，会自动在当前目录下生成log目录，log目录下会有一个日志文件，里面记录了关键的接口的测试结果和更详细一些的测试信息。部分日志消息如下图所示，**里面可以了解到某个测试是否通过以及哪个接口的测试结果，以及这个接口的返回值应该是什么。**比如select调用的测试结果是`PASS`通过，并且后面还有一小段提示：*如果这条测试失败了，需要检查一下大页内存的分配是不是超过了1024*

#### 3.2当前支持的测试范围

- int rtw_socket(int domain, int type, int protocol);
- int rtw_accept(int s, struct sockaddr *addr, socklen_t *addrlen);
- int rtw_accept4(int s, struct sockaddr *addr, socklen_t *addrlen, int flags);
- int rtw_bind(int s, const struct sockaddr *name, socklen_t namelen);
- int rtw_listen(int s, int backlog);
- int rtw_connect(int s, const struct sockaddr *name, socklen_t namelen);
- int rtw_setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen);
- int rtw_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen);
- int rtw_getpeername(int s, struct sockaddr *name, socklen_t *namelen);
- int rtw_getsockname(int s, struct sockaddr *name, socklen_t *namelen);
- ssize_t rtw_read(int s, void *mem, size_t len);
- ssize_t rtw_readv(int s, const struct iovec *iov, int iovcnt);
- ssize_t rtw_write(int s, const void *mem, size_t size);
- ssize_t rtw_writev(int s, const struct iovec *iov, int iovcnt);
- ssize_t rtw_recv(int sockfd, void *buf, size_t len, int flags);
- ssize_t rtw_send(int sockfd, const void *buf, size_t len, int flags);
- ssize_t rtw_recvmsg(int s, const struct msghdr *message, int flags);
- ssize_t rtw_sendmsg(int s, const struct msghdr *message, int flags);
- ssize_t rtw_recvfrom(int sockfd, void *buf, size_t len, int flags,
- struct sockaddr *addr, socklen_t *addrlen);
- ssize_t rtw_sendto(int sockfd, const void *buf, size_t len, int flags,
- const struct sockaddr *addr, socklen_t addrlen);
- int rtw_epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout);
- int rtw_poll(struct pollfd *fds, nfds_t nfds, int timeout);
- int rtw_close(int s);
- int rtw_shutdown(int fd, int how);
- int rtw_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
- int rtw_epoll_create1(int flags);
- int rtw_epoll_create(int flags);
- int rtw_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
- int rtc_epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout)
- int rtc_socket(int domain, int type, int protocol)
- int rtc_close(int s)
- int rtc_shutdown(int fd, int how)
- int rtc_epoll_create1(int flags)
- int rtc_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)

对`lstack_rtc_api.c`、 `lstack_rtw_api.c`的函数覆盖率达到**90%**左右。测试框架主要测试了其中的rtw与rtc的相关的接口，在`rtw_read`和`rtw_write`的接口执行过程中也涉及到了recv/send读写模块，rpc模块的调用，间接的测试了接口。

### 4.新增用例指南

举个例子，比如现在要新增一个测试用例，测试Myfunction接口。

1. 在POSIX目录下新增，一个目录`Myfunction_Test`

2. 目录里面创建两个文件

   - 测试逻辑文件 `Myfunction_test.c`，里面包含一些对接口的测试逻辑函数，*需要include "test_frame.h"头文件*，假设测试函数为`Myfunction_success()`函数和`Myfunction_failure()`函数。

   - **CMakeLists.txt**:内容相对固定，将当前文件编成共享库，stack是上一层cmake生成的直接拿来用。

     - ```cmake
       cmake_minimum_required(VERSION 3.10)
       project(MyfunctionTest VERSION 1.0)
       set(CMAKE_C_STANDARD 99)
       
       add_library(Myfunction_test_lib SHARED Myfunction_test.c)
       
       target_link_libraries(Myfunction_test_lib PUBLIC stack)
       
       ```

3. test_frame.h中声明下这个两个测试函数`Myfunction_success`和`Myfunction_failure`。

4. 最后在main函数中的CUNIT框架中添加这个两个测试用例到套件当中

   - ```c
     add_test(posix_Suite, "Testing Myfunction_success ", Myfunction_success);
     add_test(posix_Suite, "Testing Myfunction_failure ", Myfunction_failure);
     ```

     第一个参数为之前注册的测试套件，第二个为提示词，第三个为测试函数名称

5. 在最外层的CMakeLists.txt文件中，将库`Myfunction_test_lib`连接到main上

   - ```cmake
     target_link_libraries(
       main
       PRIVATE stack
               rtw_rtc_socket_test_lib
               ... ...
               Myfunction_test_lib)
     ```

     

6. 至此添加成功，重新编译即可运行测试用例，测试框架会按照顺序依次执行测试逻辑。

#### 4.1测试约束和限制

​	对相关函数进行打桩的时候，可以在测试逻辑的c文件中直接重写被打桩的函数，这样在链接的过程中gazelle的函数会被覆盖掉，从而运行自定义的桩函数。

​	但是如果桩函数是static声明的，则需要依次打桩到最上层的非static调用，因为static声明在是保护的，其它文件调用看不见。在测试逻辑中声明的static函数，也是保护的不会影响其它的单元测试接口。如果桩函数不是static的那么就会影响，因为链接完成之后是根据符号表去找函数的，同一个函数在整段程序的运行过程中只能有一种逻辑（考虑可能动态注入可能实现，没实践过）。rtc相关的单元测试尽量放在rtw的后面，在实际运行过中，如果放在bind接口的组播测试前似乎会有死锁问题。
