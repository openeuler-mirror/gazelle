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


#ifndef __UTILITIES_H__
#define __UTILITIES_H__


#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include <inttypes.h>

#include <unistd.h>
#include <pthread.h>

#include <sys/types.h>


#define PRINT_ERROR(str)                    do \
                                            { \
                                                printf("\n[error]: "); \
                                                printf(str); \
                                                printf("\n"); \
                                            } while(0)
#define PRINT_WARNNING(str)                 do \
                                            { \
                                                printf("\n[warnning]: "); \
                                                printf(str); \
                                                printf("\n"); \
                                            } while(0)
#define LIMIT_VAL_RANGE(val, min, max)      ((val) < (min) ? (min) : ((val) > (max) ? (max) : (val)))
#define CHECK_VAL_RANGE(val, min, max)      ((val) < (min) ? (false) : ((val) > (max) ? (false) : (true)))

#define PROGRAM_OK                  (0)             ///< program ok flag
#define PROGRAM_FINISH              (1)             ///< program finish flag
#define PROGRAM_FAULT               (-1)            ///< program fault flag

#define UNIX_TCP_PORT_MIN           (1024)          ///< TCP minimum port number in unix
#define UNIX_TCP_PORT_MAX           (65535)         ///< TCP minimum port number in unix
#define THREAD_NUM_MIN              (1)             ///< minimum number of thead
#define THREAD_NUM_MAX              (1000)          ///< maximum number of thead
#define MESSAGE_PKTLEN_MIN          (1)             ///< minimum length of message (1 byte)
#define MESSAGE_PKTLEN_MAX          (10485760)      ///< maximum length of message (10 Mb)

#define DEFAULT_PARAM_AS            ("server")      ///< default type
#define DEFAULT_PARAM_IP            ("127.0.0.1")   ///< default IP
#define DEFAULT_PARAM_PORT          (5050)          ///< default port
#define DEFAULT_PARAM_MODEL         ("mum")         ///< default model type
#define DEFAULT_PARAM_CONNECT_NUM   (10)            ///< default connection number
#define DEFAULT_PARAM_THREAD_NUM    (8)             ///< default thread number
#define DEFAULT_PARAM_API           ("posix")       ///< default API type
#define DEFAULT_PARAM_PKTLEN        (1024)          ///< default packet length of message
#define DEFAULT_PARAM_VERIFY        (true)          ///< default flag of message verifying
#define DEFAULT_PARAM_RINGPMD       (false)         ///< default flag of ring PMD


#endif // __UTILITIES_H__
