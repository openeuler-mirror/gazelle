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


#ifndef __EXAMPLES_BUSSINESS_H__
#define __EXAMPLES_BUSSINESS_H__


#include "utilities.h"
#include "parameter.h"


#define BUSSINESS_MESSAGE_SIZE                  26                          ///< the size of business message


/**
 * @brief server handler
 * The server handler.
 */
struct ServerHandler
{
    int32_t listen_fd_array[PROTOCOL_MODE_MAX];
    int32_t fd;                 ///< socket file descriptor
    int32_t is_v6;
    int32_t index;
};

/**
 * @brief client handler
 * The client handler.
 */
struct ClientHandler
{
    int32_t fd;                 ///< socket file descriptor
    uint32_t msg_idx;           ///< the start charactors index of message
    int32_t sendtime_interverl; ///< udp send packet interverl
};


/**
 * @brief read by specify api
 * This function processes the reading by specify api.
 * @param fd            the file descriptor
 * @param buffer_in     the input buffer
 * @param length        the length
 * @param api           the type of api
 * @return              the result
 */
 int32_t read_api(int32_t fd, char *buffer_in, const uint32_t length, const char *api);

/**
 * @brief write by specify api
 * This function processes the writing by specify api.
 * @param fd            the file descriptor
 * @param buffer_out    the output buffer
 * @param length        the length
 * @param api           the type of api
 * @return              the result
 */
 int32_t write_api(int32_t fd, char *buffer_out, const uint32_t length, const char *api);

/**
 * @brief the business processsing of server
 * This function processes the business of server.
 * @param out           the output string
 * @param in            the input string
 * @param size          the size of input and output
 * @param verify        if we verify or not
 * @return              the result
 */
void server_bussiness(char *out, const char *in, uint32_t size);

/**
 * @brief the business processsing of client
 * This function processes the business of client.
 * @param out           the output string
 * @param in            the input string
 * @param size          the size of input and output
 * @param verify        if we verify or not
 * @param msg_idx       the start charactors index of message
 * @return              the result
 */
int32_t client_bussiness(char *out, const char *in, uint32_t size, bool verify, uint32_t *msg_idx);

/**
 * @brief server checks the information and answers
 * This function checks the information and answers.
 * @param fd                socket_fd
 * @param pktlen            the length of package
 * @param api               the api
 * @return                  the result
 */
int32_t server_ans(int32_t fd, uint32_t pktlen, const char *api, const char* domain, int epfd_write);

/**
 * @brief client asks server
 * This function asks server.
 * @param client_handler    client handler
 * @param client_unit       ClientUnit
 * @return                  the result
 */
int32_t client_ask(struct ClientHandler *client_handler, struct ClientUnit *client_unit);
/**
 * @brief client checks the information and answers
 * This function checks the information and answers.
 * @param client_handler    client handler
 * @param pktlen            the length of package
 * @param verify            verify or not
 * @param api               the api
 * @param domain            the domain
 * @param ip                the ip address of peer, maybe group ip
 * @return                  the result
 */
int32_t client_chkans(struct ClientHandler *client_handler, uint32_t pktlen, bool verify, const char* api, const char* domain, ip_addr_t* ip);


#endif // __EXAMPLES_BUSSINESS_H__
