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


#ifndef __EXAMPLES_UTILITIES_H__
#define __EXAMPLES_UTILITIES_H__


#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include <inttypes.h>
#include <unistd.h>
#include <ctype.h>

#include <fcntl.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include <netinet/in.h>
#include <arpa/inet.h>


#define PRINT_ERROR(format, ...)            do \
                                            { \
                                                printf("\n[error]: "); \
                                                printf(format, ##__VA_ARGS__); \
                                                printf("\n"); \
                                            } while (0)
#define PRINT_WARNNING(format, ...)         do \
                                            { \
                                                printf("\n[warnning]: "); \
                                                printf(format, ##__VA_ARGS__); \
                                                printf("\n"); \
                                            } while (0)
#define PRINT_SERVER(format, ...)           do \
                                            { \
                                                printf("<server>: "); \
                                                printf(format, ##__VA_ARGS__); \
                                                printf("\n"); \
                                            } while(0)
#define PRINT_CLIENT(format, ...)           do \
                                            { \
                                                printf("<client>: "); \
                                                printf(format, ##__VA_ARGS__); \
                                                printf("\n"); \
                                            } while(0)
#define LIMIT_VAL_RANGE(val, min, max)      ((val) < (min) ? (min) : ((val) > (max) ? (max) : (val)))
#define CHECK_VAL_RANGE(val, min, max)      ((val) < (min) ? (false) : ((val) > (max) ? (false) : (true)))

#define PROGRAM_OK                  (0)             ///< program ok flag
#define PROGRAM_ABORT               (1)             ///< program abort flag
#define PROGRAM_FAULT               (-1)            ///< program fault flag

#define UNIX_TCP_PORT_MIN           (1024)          ///< TCP minimum port number in unix
#define UNIX_TCP_PORT_MAX           (65535)         ///< TCP minimum port number in unix
#define THREAD_NUM_MIN              (1)             ///< minimum number of thead
#define THREAD_NUM_MAX              (1000)          ///< maximum number of thead
#define MESSAGE_PKTLEN_MIN          (1)             ///< minimum length of message (1 byte)
#define MESSAGE_PKTLEN_MAX          (10485760)      ///< maximum length of message (10 Mb)


#endif // __EXAMPLES_UTILITIES_H__
