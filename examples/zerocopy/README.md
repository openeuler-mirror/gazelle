这是一个ET模式的单线程C/S模型，client使用内核标准库的socket api，server 使用`gazelle`的`rtc`模式socket api。

client:
- `-i`: Server ip
- `-p`: server port(默认 5050)
- `-P`: pktlen
- `-n`: socket connection num

eg: `./client -i 192.168.66.24 -p 5050 -P 1024 -n 1`

server:
- `-A`: api
- `-i`: Server ip
- `-P`: pktlen
eg:`sudo LD_LIBRARY_PATH=/home/server/gazelle_my/src/lstack:$LD_LIBRARY_PATH LD_PRELOAD=/home/server/gazelle_my/src/lstack/liblstack.so GAZELLE_BIND_PROCNAME=server ./server -A zerocopy_readwrite -i 192.168.66.24 -P 1024`
