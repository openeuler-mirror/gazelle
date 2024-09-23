SRC = api_lib.c api_msg.c err.c netbuf.c netdb.c netifapi.c sockets.c tcpip.c \
	  sys_arch.c lwipgz_posix_api.c lwipgz_sock.c

$(eval $(call register_dir, api, $(SRC)))
