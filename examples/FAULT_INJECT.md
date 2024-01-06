# Gazelle 故障注入 说明

## 需求
1. example:构造黑盒故障
   * 延迟类：accept|read：
     * accept: 构造tcp_acceptmbox_full的情景.
     * read: 构造tcp_refuse_count、recvmbox满
   * 跳过类：跳过 read/write并close：
     * read: 构造链接关闭时时4次挥手的情景,验证TCP状态机。
2. gazelle/lwip: 构造白盒故障，支持注入故障报文、协议栈状态、事件设置、资源异常等
   * 编译宏支持
   * 提供接口：配置文件、env
   * 故障报文注入：
     * 类似内核tc工具：
       * 内核TC工具qdisc指令原理：报文分组被添加到网卡队列（qdisc），该队列决定发包顺序。<br>
       qdisc指令可以在队列层面实现延时、丢包、重复等故障。
       * dpdk性能检测工具testpmd可以模拟实现类似的故障模拟，testpmd与gazelle不兼容，需要参考其中调用的dpdk接口来改gazelle代码。<br>
       * 延时故障
       * 丢包故障
         - 思路：调整网卡队列，随机丢弃百分比的包，然后发送。
         - 函数调用：rte_rand()，rte_eth_tx_burst()。
       * 包重复故障
       * 随机故障
       * 乱序故障
   * 协议栈状态故障
     * ...
   * 事件设置
     * ...
   * 资源异常
     * 资源耗尽，无法申请。
     * ...
 
 
