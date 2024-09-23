SRC = def.c inet_chksum.c init.c ip.c mem.c memp.c netif.c pbuf.c \
	  raw.c tcp.c tcp_in.c tcp_out.c timeouts.c udp.c stats.c\
	  ipv4/icmp.c ipv4/ip4_addr.c ipv4/ip4_frag.c ipv4/etharp.c \
	  ipv4/ip4.c ipv4/igmp.c ipv6/icmp6.c ipv6/ip6_addr.c ipv6/ip6_frag.c \
	  ipv6/ethip6.c ipv6/ip6.c ipv6/dhcp6.c ipv6/inet6.c \
	  ipv6/mld6.c ipv6/nd6.c mcast.c

$(eval $(call register_dir, core, $(SRC)))
