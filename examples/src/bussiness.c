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


static const char bussiness_messages_low[] = "abcdefghijklmnopqrstuvwxyz";  // the lower charactors of business message
static const char bussiness_messages_cap[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";  // the capital charactors of business message


// read by specify api
 int32_t read_api(int32_t fd, char *buffer_in, const uint32_t length, const char *api)
 {
    if (strcmp(api, "readwrite") == 0) {
        return read(fd, buffer_in, length);
    } else if (strcmp(api, "recvsend") == 0) {
        return recv(fd, buffer_in, length, 0);
    } else if (strcmp(api, "readvwritev") == 0) {
        struct iovec iov[3];
        int iovcnt = 3;
        uint32_t iov_len_size = length/iovcnt;

        iov[0].iov_base=buffer_in;
        iov[0].iov_len = iov_len_size;
        iov[1].iov_base= buffer_in + iov_len_size;
        iov[1].iov_len =  iov_len_size;
        iov[2].iov_base = buffer_in + iov_len_size + iov_len_size;
        iov[2].iov_len = length- iov_len_size - iov_len_size;
        return readv(fd, iov, iovcnt);
    } else if (strcmp(api, "recvsendmsg") == 0) {
        struct msghdr msg_recv;
        struct iovec iov;

        msg_recv.msg_name = NULL;
        msg_recv.msg_namelen = 0;
        msg_recv.msg_iov = &iov;
        msg_recv.msg_iovlen = 1;
        msg_recv.msg_iov->iov_base = buffer_in;
        msg_recv.msg_iov->iov_len = length;
        msg_recv.msg_control = 0;
        msg_recv.msg_controllen = 0;
        msg_recv.msg_flags = 0;

        return recvmsg(fd, &msg_recv, 0);
    } else {
        return recvfrom(fd, buffer_in, length, 0, NULL, 0);
    }
 }

// write by specify api
 int32_t write_api(int32_t fd, char *buffer_out, const uint32_t length, const char *api)
 {
    if (strcmp(api, "readwrite") == 0) {
        return write(fd, buffer_out, length);
    } else if (strcmp(api, "recvsend") == 0) {
        return send(fd, buffer_out, length, 0);
    } else if (strcmp(api, "readvwritev") == 0) {
        struct iovec iov[3];
        int iovcnt = 3;
        uint32_t iov_len_size = length/iovcnt;

        iov[0].iov_base=buffer_out;
        iov[0].iov_len = iov_len_size;
        iov[1].iov_base= buffer_out + iov_len_size;
        iov[1].iov_len =  iov_len_size;
        iov[2].iov_base = buffer_out + iov_len_size + iov_len_size;
        iov[2].iov_len = length- iov_len_size - iov_len_size;
        
        return writev(fd, iov, iovcnt);
    } else if (strcmp(api, "recvsendmsg") == 0) {
        struct msghdr msg_send;
        struct iovec iov;

        msg_send.msg_name = NULL;
        msg_send.msg_namelen = 0;
        msg_send.msg_iov = &iov;
        msg_send.msg_iovlen = 1;
        msg_send.msg_iov->iov_base = buffer_out;
        msg_send.msg_iov->iov_len = length;
        msg_send.msg_control = 0;
        msg_send.msg_controllen = 0;
        msg_send.msg_flags = 0;

        return sendmsg(fd, &msg_send, 0);
    } else {
        return sendto(fd, buffer_out, length, 0, NULL, 0);
    }
 }

// the business processsing of server
void server_bussiness(char *out, const char *in, uint32_t size)
{
    char diff = 'a' - 'A';
    for (uint32_t i = 0; i < size; ++i) {
        if (in[i] != '\0') {
            out[i] = in[i] - diff;
        } else {
            out[i] = '\0';
        }
    }
}

// the business processsing of client
int32_t client_bussiness(char *out, const char *in, uint32_t size, bool verify, uint32_t *msg_idx)
{
    if (verify == false) {
        for (uint32_t i = 0; i < (size - 1); ++i) {
            out[i] = bussiness_messages_low[(*msg_idx + i) % BUSSINESS_MESSAGE_SIZE];
        }
    } else {
        uint32_t verify_start_idx = (*msg_idx == 0) ? (BUSSINESS_MESSAGE_SIZE - 1) : (*msg_idx - 1);
        for (uint32_t i = 0; i < (size - 1); ++i) {
            if (in[i] != bussiness_messages_cap[(verify_start_idx + i) % BUSSINESS_MESSAGE_SIZE]) {
                return PROGRAM_FAULT;
            }
            out[i] = bussiness_messages_low[(*msg_idx + i) % BUSSINESS_MESSAGE_SIZE];
        }
    }
    out[size - 1] = '\0';

    ++(*msg_idx);
    *msg_idx = (*msg_idx) % BUSSINESS_MESSAGE_SIZE;

    return PROGRAM_OK;
}

// server answers
int32_t server_ans(struct ServerHandler *server_handler, uint32_t pktlen, const char* api, const char* domain)
{
    const uint32_t length = pktlen;
    char *buffer_in = (char *)malloc(length * sizeof(char));
    char *buffer_out = (char *)malloc(length * sizeof(char));

    int32_t cread = 0;
    int32_t sread = length;
    int32_t nread = 0;
    struct sockaddr_in client_addr;
    socklen_t len = sizeof(client_addr);

    if (strcmp(domain, "udp") == 0 && strncmp(api, "recvfrom", strlen("recvfrom")) != 0) {
        if (getpeername(server_handler->fd, (struct sockaddr *)&client_addr, &len) < 0) {
            if (recvfrom(server_handler->fd, buffer_in, length, MSG_PEEK, (struct sockaddr *)&client_addr, &len) < 0) {
                return PROGRAM_FAULT;
            }
            if (connect(server_handler->fd, (struct sockaddr *)&client_addr, sizeof(struct sockaddr_in)) < 0) {
                return PROGRAM_FAULT;
            }
        }
    }

    while (cread < sread) {
        if (strcmp(domain, "udp") == 0 && strcmp(api, "recvfromsendto") == 0) {
            nread = recvfrom(server_handler->fd, buffer_in, length, 0, (struct sockaddr *)&client_addr, &len);
        } else {
            nread = read_api(server_handler->fd, buffer_in, length, api);
        }

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

    if (strcmp(api, "recvfrom") == 0) {
        free(buffer_in);
        free(buffer_out);
        return PROGRAM_OK;
    }

    server_bussiness(buffer_out, buffer_in, length);

    int32_t cwrite = 0;
    int32_t swrite = length;
    int32_t nwrite = 0;
    while (cwrite < swrite) {
        if (strcmp(domain, "udp") == 0 && strcmp(api, "recvfromsendto") == 0) {
            nwrite = sendto(server_handler->fd, buffer_out, length, 0, (struct sockaddr *)&client_addr, len);
        } else {
            nwrite = write_api(server_handler->fd, buffer_out, length, api);
        }

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

    free(buffer_in);
    free(buffer_out);

    return PROGRAM_OK;
}

// client asks
int32_t client_ask(struct ClientHandler *client_handler, uint32_t pktlen, const char* api, const char* domain, in_addr_t ip, uint16_t port)
{
    const uint32_t length = pktlen;
    char *buffer_in = (char *)malloc(length * sizeof(char));
    char *buffer_out = (char *)malloc(length * sizeof(char));
    struct sockaddr_in server_addr;
    socklen_t len = sizeof(server_addr);
    memset_s(&server_addr, sizeof(server_addr), 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = ip;
    server_addr.sin_port = port;

    client_bussiness(buffer_out, buffer_in, length, false, &(client_handler->msg_idx));

    int32_t cwrite = 0;
    int32_t swrite = length;
    int32_t nwrite = 0;
    while (cwrite < swrite) {
        if (strcmp(domain, "udp") == 0 && strcmp(api, "recvfromsendto") == 0) {
            nwrite = sendto(client_handler->fd, buffer_out, length, 0, (struct sockaddr *)&server_addr, len);
        } else {
            nwrite = write_api(client_handler->fd, buffer_out, length, api);
        }
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

    free(buffer_in);
    free(buffer_out);

    return PROGRAM_OK;
}

// client checks
int32_t client_chkans(struct ClientHandler *client_handler, uint32_t pktlen, bool verify, const char* api, const char* domain, in_addr_t ip)
{
    const uint32_t length = pktlen;
    char *buffer_in = (char *)malloc(length * sizeof(char));
    char *buffer_out = (char *)malloc(length * sizeof(char));

    int32_t cread = 0;
    int32_t sread = length;
    int32_t nread = 0;
    struct sockaddr_in server_addr;
    socklen_t len = sizeof(server_addr);

    while (cread < sread) {
        if (strcmp(domain, "udp") == 0 && strcmp(api, "recvfromsendto") == 0) {
            nread = recvfrom(client_handler->fd, buffer_in, length, 0, (struct sockaddr *)&server_addr, &len);
        } else {
            nread = read_api(client_handler->fd, buffer_in, length, api);
        }
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

    if (client_bussiness(buffer_out, buffer_in, length, verify, &(client_handler->msg_idx)) < 0) {
        PRINT_ERROR("message verify fault! ");
        getchar();
    }

    int32_t cwrite = 0;
    int32_t swrite = length;
    int32_t nwrite = 0;
    if (ip >= inet_addr("224.0.0.0") && ip <= inet_addr("239.255.255.255")) {
        server_addr.sin_addr.s_addr = ip;
    }

    while (cwrite < swrite) {
        if (strcmp(domain, "udp") == 0 && strcmp(api, "recvfromsendto") == 0) {
            nwrite = sendto(client_handler->fd, buffer_out, length, 0, (struct sockaddr *)&server_addr, len);
        } else {
            nwrite = write_api(client_handler->fd, buffer_out, length, api);
        }
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

    free(buffer_in);
    free(buffer_out);

    return PROGRAM_OK;
}
