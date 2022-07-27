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


static const char bussiness_messages_low[] = "abcdefghijklmnopqrstuvwxyz";  ///< the lower charactors of business message
static const char bussiness_messages_cap[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";  ///< the capital charactors of business message


/**
 * @brief the business processsing of server
 * This function processes the business of server.
 * @param in            the input string
 * @param out           the output string
 * @param size          the size of input and output
 * @param verify        if we verify or not
 * @param msg_idx       the start charactors index of message
 * @return              the result
 */
int32_t server_bussiness(const char *in, char *out, uint32_t size, bool verify, uint32_t *msg_idx);

/**
 * @brief the business processsing of client
 * This function processes the business of client.
 * @param in            the input string
 * @param out           the output string
 * @param size          the size of input and output
 * @param verify        if we verify or not
 * @param msg_idx       the start charactors index of message
 * @return              the result
 */
int32_t client_bussiness(const char *in, char *out, uint32_t size, bool verify, uint32_t *msg_idx);

/**
 * @brief server checks the information and answers
 * This function checks the information and answers.
 * @param connect_fd    the conneced client's file descriptor
 * @param pktlen        the length of packet
 * @param verify        verify the packet or not
 * @param msg_idx       the start charactors index of message
 * @return              the result
 */
int32_t server_chk_ans(int32_t connect_fd, uint32_t pktlen, bool verify, uint32_t *msg_idx);

/**
 * @brief client asks server
 * This function asks server.
 * @param connect_fd    the conneced client's file descriptor
 * @param pktlen        the length of packet
 * @param verify        verify the packet or not
 * @param msg_idx       the start charactors index of message
 * @return              the result
 */
int32_t client_ask(int32_t connect_fd, uint32_t pktlen, bool verify, uint32_t *msg_idx);

/**
 * @brief client checks the information and answers
 * This function checks the information and answers.
 * @param connect_fd    the conneced client's file descriptor
 * @param pktlen        the length of packet
 * @param verify        verify the packet or not
 * @param msg_idx       the start charactors index of message
 * @return              the result
 */
int32_t client_chk_ans(int32_t connect_fd, uint32_t pktlen, bool verify, uint32_t *msg_idx);


#endif // __EXAMPLES_BUSSINESS_H__
