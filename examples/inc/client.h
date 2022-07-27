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


#ifndef __EXAMPLES_CLIENT_H__
#define __EXAMPLES_CLIENT_H__


#include "utilities.h"
#include "parameter.h"
#include "bussiness.h"


/**
 * @brief client unit
 * The information of each thread of client.
 */
struct ClientUnit
{
    int32_t *cnntfds;           ///< the connect socket file descriptor
    int32_t epfd;               ///< the connect epoll file descriptor
    struct epoll_event *epevs;  ///< the epoll events
    pthread_mutex_t *lock;      ///< mutex lock
    uint32_t connections;       ///< current connections
    char *ip;                   ///< server ip
    uint32_t port;              ///< server port
    uint32_t connect_num;       ///< connect number
    uint32_t pktlen;            ///< the length of peckage
    bool verify;                ///< if we verify the message or not
    uint32_t msg_idx;           ///< the start charactors index of message
    bool debug;                 ///< if we print the debug information
};


/**
 * @brief the single thread, client prints informations
 * The single thread, client prints informations.
 * @param arg           each thread's information of server
 * @return              the result pointer
 */
void clithd_debug_print(struct ClientUnit *client_unit, const char *str, const char *ip, uint32_t port);

/**
 * @brief the single thread, client connects and gets epoll feature descriptors
 * The single thread, client connects and gets epoll feature descriptors.
 * @param arg           each thread's information of server
 * @return              the result pointer
 */
int32_t clithd_get_epfd(struct ClientUnit *client_unit);

/**
 * @brief create client of single thread
 * This function creates client of single thread.
 * @param arg           each thread's information of server
 * @return              the result pointer
 */
void *client_s_create(void *arg);

/**
 * @brief create client
 * This function create the client.
 * @param params        the parameters pointer
 * @return              the result
 */
int32_t client_create(struct ProgramParams *params);


#endif // __EXAMPLES_CLIENT_H__
