/*
* Copyright (c) 2022-2023. yyangoO.
* gazelle is licensed under the Mulan PSL v2.
* You can use this software according to the terms and conditions of the Mulan PSL v2.
* You may obtain a copy of Mulan PSL v2 at:
*     http://license.coscl.org.cn/MulanPSL2
* THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
* PURPOSE.
* See the Mulan PSL v2 for more details.
*/


#ifndef __EXAMPLES_SERVER_H__
#define __EXAMPLES_SERVER_H__
#define _GNU_SOURCE 

#include "utilities.h"
#include "parameter.h"
#include "bussiness.h"


/**
 * @brief server unit of model mum
 * The information of each thread of server of model mum.
 */
struct ServerMumUnit
{
    struct ServerHandler listener;          ///< the listen handler
    int32_t epfd;                           ///< the listen epoll file descriptor
    struct epoll_event *epevs;              ///< the epoll events
    uint32_t curr_connect;                  ///< current connection number
    uint64_t recv_bytes;                    ///< total receive bytes
    ip_addr_t ip;                           ///< server ip
    ip_addr_t groupip;                      ///< server group ip
    uint16_t port;                          ///< server port
    uint32_t pktlen;                        ///< the length of peckage
    char* domain;                           ///< communication domain
    char* api;                              ///< the type of api
    bool debug;                             ///< if we print the debug information
    char* epollcreate;                      ///< epoll_create method
    char* accept;                           ///< accept connections method
    int32_t tcp_keepalive_idle;             ///< tcp keepalive idle time
    int32_t tcp_keepalive_interval;         ///< tcp keepalive interval time
    uint8_t protocol_type_mode;             ///< tcp/udp ipv4/ipv6 protocol mode
    struct ServerMumUnit *next;             ///< next pointer
};

/**
 * @brief server model mum
 * The information of server model mum.
 */
struct ServerMum
{
    struct ServerMumUnit *uints;            ///< the server mum unit
    bool debug;                             ///< if we print the debug information
};

/**
 * @brief server unit of model mud worker unit
 * The information of worker unit of server of model mud.
 */
struct ServerMudWorker
{
    struct ServerHandler worker;            ///< the worker handler
    int32_t epfd;                           ///< the worker epoll file descriptor
    struct epoll_event *epevs;              ///< the epoll events
    uint64_t recv_bytes;                    ///< total receive bytes
    uint32_t pktlen;                        ///< the length of peckage
    ip_addr_t ip;                           ///< client ip
    uint16_t port;                          ///< client port
    char* api;                              ///< the type of api
    bool debug;                             ///< if we print the debug information
    char* epollcreate;                      ///< epoll_create method
    char* domain;
    uint32_t curr_connect;
    struct ServerMudWorker *next;           ///< next pointer
};

/**
 * @brief server model mud
 * The information of server model mud.
 */
struct ServerMud
{
    struct ServerHandler listener;          ///< the listen handler
    struct ServerMudWorker *workers;        ///< the workers
    int32_t epfd;                           ///< the listen epoll file descriptor
    struct epoll_event *epevs;              ///< the epoll events
    ip_addr_t ip;                           ///< server ip
    ip_addr_t groupip;                      ///< server group ip
    bool* port;                             ///< server port point to parameter's port
    uint32_t pktlen;                        ///< the length of peckage
    char* domain;                           ///< communication domain
    char* api;                              ///< the type of api
    bool debug;                             ///< if we print the debug information
    char* accept;                           ///< accept connections method
    char* epollcreate;                      ///< epoll_create method
    int32_t tcp_keepalive_idle;             ///< tcp keepalive idle time
    int32_t tcp_keepalive_interval;         ///< tcp keepalive interval time
    uint8_t protocol_type_mode;             ///< tcp/udp ipv4/ipv6 protocol mode
};


/**
 * @brief the worker thread, unblock, dissymmetric server prints debug informations
 * The worker thread, unblock, dissymmetric server prints debug informations.
 * @param ch_str            the charactor string
 * @param act_str           the action string
 * @param ip                the ip address
 * @param port              the port
 * @param debug             if debug or not
 * @return                  the result pointer
 */
void server_debug_print(const char *ch_str, const char *act_str, ip_addr_t *ip, uint16_t port, bool debug);

/**
 * @brief the multi thread, unblock, dissymmetric server prints informations
 * The multi thread, unblock, dissymmetric server prints informations.
 * @param server_mud        the server information
 */
void sermud_info_print(struct ServerMud *server_mud);

/**
 * @brief the worker thread, unblock, dissymmetric server listens and gets epoll feature descriptors
 * The worker thread, unblock, dissymmetric server listens and gets epoll feature descriptors.
 * @param worker_unit       the server worker
 * @return                  the result pointer
 */
int32_t sermud_worker_create_epfd_and_reg(struct ServerMudWorker *worker_unit);

/**
 * @brief the listener thread, unblock, dissymmetric server listens and gets epoll feature descriptors
 * The listener thread, unblock, dissymmetric server listens and gets epoll feature descriptors.
 * @param server_mud        the server unit
 * @return                  the result pointer
 */
int32_t sermud_listener_create_epfd_and_reg(struct ServerMud *server_mud);

/**
 * @brief the listener thread, unblock, dissymmetric server accepts the connections
 * The listener thread, unblock, dissymmetric server accepts the connections.
 * @param server_mud        the server unit
 * @return                  the result pointer
 */
int32_t sermud_listener_accept_connects(struct epoll_event *curr_epev, struct ServerMud *server_mud);

/**
 * @brief the worker thread, unblock, dissymmetric server processes the events
 * The worker thread, unblock, dissymmetric server processes the events.
 * @param worker_unit       the server worker
 * @return                  the result pointer
 */
int32_t sermud_worker_proc_epevs(struct ServerMudWorker *worker_unit, const char* domain);

/**
 * @brief the listener thread, unblock, dissymmetric server processes the events
 * The listener thread, unblock, dissymmetric server processes the events.
 * @param server_mud        the server unit
 * @return                  the result pointer
 */
int32_t sermud_listener_proc_epevs(struct ServerMud *server_mud);

/**
 * @brief create the worker thread, unblock, dissymmetric server and run
 * This function creates the worker thread, unblock, dissymmetric server and run.
 * @param arg           each thread's information of server
 * @return              the result pointer
 */
void *sermud_worker_create_and_run(void *arg);

/**
 * @brief create the listener thread, unblock, dissymmetric server and run
 * This function creates the listener thread, unblock, dissymmetric server and run.
 * @param arg           each thread's information of server
 * @return              the result pointer
 */
void *sermud_listener_create_and_run(void *arg);

/**
 * @brief create the multi thread, unblock, dissymmetric server and run
 * This function creates the multi thread, unblock, dissymmetric server and run.
 * @param params        the parameters pointer
 * @return              the result
 */
int32_t sermud_create_and_run(struct ProgramParams *params);

/**
 * @brief the multi thread, unblock, mutliplexing IO server prints informations
 * The multi thread, unblock, mutliplexing IO server prints informations.
 * @param server_mum        the server information
 */
void sermum_info_print(struct ServerMum *server_mum);

/**
 * @brief the single thread, unblock, mutliplexing IO server listens and gets epoll feature descriptors
 * The single thread, unblock, mutliplexing IO server listens and gets epoll feature descriptors.
 * @param server_unit       the server unit
 * @return                  the result pointer
 */
int32_t sersum_create_epfd_and_reg(struct ServerMumUnit *server_unit);

/**
 * @brief the single thread, unblock, mutliplexing IO server accepts the connections
 * The single thread, unblock, mutliplexing IO server accepts the connections.
 * @param server_unit       the server unit
 * @param server_handler    the server handler
 * @return                  the result pointer
 */
int32_t sersum_accept_connects(struct epoll_event *cur_epev, struct ServerMumUnit *server_unit);

/**
 * @brief the single thread, unblock, mutliplexing IO server processes the events
 * The single thread, unblock, mutliplexing IO server processes the events.
 * @param server_unit       the server unit
 * @return                  the result pointer
 */
int32_t sersum_proc_epevs(struct ServerMumUnit *server_unit);

/**
 * @brief create the single thread, unblock, mutliplexing IO server
 * This function creates the single thread, unblock, mutliplexing IO server.
 * @param arg           each thread's information of server
 * @return              the result pointer
 */
void *sersum_create_and_run(void *arg);

/**
 * @brief create the multi thread, unblock, mutliplexing IO server and run
 * This function creates the multi thread, unblock, mutliplexing IO server and run.
 * @param params        the parameters pointer
 * @return              the result
 */
int32_t sermum_create_and_run(struct ProgramParams *params);

/**
 * @brief create server and run
 * This function create the specify server and run.
 * @param params        the parameters pointer
 * @return              the result
 */
int32_t server_create_and_run(struct ProgramParams *params);


#endif // __EXAMPLES_SERVER_H__
