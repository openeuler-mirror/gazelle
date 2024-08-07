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

#define TIME_SCAN_INTERVAL 1
#define TIME_SEND_INTERVAL 1

/**
 * @brief client
 * The information of client.
 */
struct Client
{
    struct ClientUnit *uints;           ///< the server mum unit
    bool debug;                         ///< if we print the debug information
    uint32_t threadNum;
    bool loop;                          ///< judge client info print while loop is open
};

struct Client_domain_ip {
    char *domain;
    uint8_t ip_family;
};

/**
 * @brief the single thread, client prints informations
 * The single thread, client prints informations.
 * @param ch_str            the charactor string
 * @param act_str           the action string
 * @param ip                the ip address
 * @param port              the port
 * @param debug             if debug or not
 * @return                  the result pointer
 */
void client_debug_print(const char *ch_str, const char *act_str, ip_addr_t *ip, uint16_t port, bool debug);

/**
 * @brief the client prints informations
 * The client prints informations.
 * @param client            the client information
 */
void client_info_print(struct Client *client);

/**
 * @brief the single thread, client try to connect to server, register to epoll
 * The single thread, client try to connect to server, register to epoll.
 * @param client_handler    the client handler
 * @param epoll_fd          the epoll file descriptor
 * @param ip                ip address
 * @param port              port
 * @param sport             sport
 * @param domain            domain
 * @return                  the result pointer
 */
int32_t client_thread_try_connect(struct ClientHandler *client_handler, struct ClientUnit *client_unit);

/**
 * @brief the single thread, client retry to connect to server, register to epoll
 * The single thread, client retry to connect to server, register to epoll.
 * @param client_unit       the client unit
 * @param client_handler    the client handler
 * @return                  the result pointer
 */
int32_t client_thread_retry_connect(struct ClientUnit *client_unit, struct ClientHandler *client_handler);

/**
 * @brief the single thread, client connects and gets epoll feature descriptors
 * The single thread, client connects and gets epoll feature descriptors.
 * @param client_unit   the client unit
 * @return              the result pointer
 */
int32_t client_thread_create_epfd_and_reg(struct ClientUnit *client_unit);

/**
 * @brief create client of single thread and run
 * This function creates client of single thread and run.
 * @param arg           each thread's information of server
 * @return              the result pointer
 */
void *client_s_create_and_run(void *arg);

/**
 * @brief create client and run
 * This function create the client and run.
 * @param params        the parameters pointer
 * @return              the result
 */
int32_t client_create_and_run(struct ProgramParams *params);


/**
 * @brief loop server info
 * This function print loop mode server info.
 */
void loop_info_print();


#endif // __EXAMPLES_CLIENT_H__
