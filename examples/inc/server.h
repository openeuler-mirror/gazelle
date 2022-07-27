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


#include "utilities.h"
#include "parameter.h"
#include "bussiness.h"


/**
 * @brief server unit of model mum
 * The information of each thread of server of model mum.
 */
struct ServerMumUnit
{
    int32_t lstnfd;             ///< the listen socket file descriptor
    int32_t epfd;               ///< the listen epoll file descriptor
    struct epoll_event *epevs;  ///< the epoll events
    uint32_t connections;       ///< current connections
    pthread_mutex_t *lock;      ///< mutex lock
    char *ip;                   ///< server ip
    uint32_t port;              ///< server port
    uint32_t pktlen;            ///< the length of peckage
    bool verify;                ///< if we verify the message or not
    uint32_t msg_idx;           ///< the start charactors index of message
    bool debug;                 ///< if we print the debug information
};


/**
 * @brief the single thread, unblock, mutliplexing IO server listens and gets epoll feature descriptors
 * The single thread, unblock, mutliplexing IO server listens and gets epoll feature descriptors.
 * @param server_unit       the server unit
 * @return                  the result pointer
 */
// the single thread, unblock, mutliplexing IO server listens and gets epoll feature descriptors
int32_t sersum_get_epfd(struct ServerMumUnit *server_unit);

/**
 * @brief the single thread, unblock, mutliplexing IO server prints debug informations
 * The single thread, unblock, mutliplexing IO server prints debug informations.
 * @param server_unit       the server unit
 * @param str               the debug information
 * @param ip                the ip address
 * @param port              the port
 * @return                  the result pointer
 */
void sersum_debug_print(struct ServerMumUnit *server_unit, const char *str, const char *ip, uint32_t port);

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
void *sersum_create(void *arg);

/**
 * @brief create the multi thread, unblock, mutliplexing IO server
 * This function creates the multi thread, unblock, mutliplexing IO server.
 * @param params        the parameters pointer
 * @return              the result
 */
int32_t sermum_create(struct ProgramParams *params);

/**
 * @brief create server
 * This function create the specify server.
 * @param params        the parameters pointer
 * @return              the result
 */
int32_t server_create(struct ProgramParams *params);


#endif // __EXAMPLES_SERVER_H__
