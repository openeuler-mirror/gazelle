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


#include "bussiness.h"


// the business processsing of server
int32_t server_bussiness(const char *in, char *out, uint32_t size, bool verify, uint32_t *msg_idx)
{
    if (verify == true) {
        int buss_msg_idx = *msg_idx;
        for (int i = 0; i < size; ++i) {
            char cursor = in[i];

            if (cursor == bussiness_messages_low[buss_msg_idx]) {
                out[i] = bussiness_messages_cap[buss_msg_idx];

                ++buss_msg_idx;
                if (buss_msg_idx >= BUSSINESS_MESSAGE_SIZE) {
                    buss_msg_idx = 0;
                }
            } else {
                return PROGRAM_FAULT;
            }
        }

        ++(*msg_idx);
        if (*msg_idx >= BUSSINESS_MESSAGE_SIZE) {
            *msg_idx = 0;
        }
    }
    return PROGRAM_OK;
}

// the business processsing of client
int32_t client_bussiness(const char *in, char *out, uint32_t size, bool verify, uint32_t *msg_idx)
{
    return PROGRAM_OK;
}

// server checks the information and answers
int32_t server_chk_ans(int32_t connect_fd, uint32_t pktlen, bool verify, uint32_t *msg_idx)
{
    const uint32_t length = pktlen;
    char buffer_in[length];
    char buffer_out[length];

    memset(buffer_in, 0, length);
    memset(buffer_out, 0, length);

    int32_t cread = 0;
    int32_t sread = length;
    while (cread < sread) {
        int32_t nread = read(connect_fd, buffer_in, length);
        if (nread == 0) {
            return PROGRAM_ABORT;
        } else if (nread < 0) {
             if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN) {
                return PROGRAM_FAULT;
             }
        } else {
            cread += nread;
            continue;
        }
    }

    if (server_bussiness(buffer_in, buffer_out, length, verify, msg_idx) < 0) {
        PRINT_WARNNING("message verify fault! ");
    }

    int32_t cwrite = 0;
    int32_t swrite = length;
    while (cwrite < swrite) {
        int32_t nwrite = write(connect_fd, buffer_out, length);
        if (nwrite == 0) {
            return PROGRAM_ABORT;
        } else if (nwrite < 0) {
             if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN) {
                return PROGRAM_FAULT;
             }
        } else {
            cwrite += nwrite;
            continue;
        }
    }

    return PROGRAM_OK;
}

// client asks server
int32_t client_ask(int32_t connect_fd, uint32_t pktlen, bool verify, uint32_t *msg_idx)
{
    return PROGRAM_OK;
}

// client checks the information and answers
int32_t client_chk_ans(int32_t connect_fd, uint32_t pktlen, bool verify, uint32_t *msg_idx)
{
    return PROGRAM_OK;
}