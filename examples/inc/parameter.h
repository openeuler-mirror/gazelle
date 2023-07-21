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


#ifndef __EXAMPLES_PARAMETER_H__
#define __EXAMPLES_PARAMETER_H__


#include "utilities.h"


#define PARAM_DEFAULT_AS            ("server")              ///< default type
#define PARAM_DEFAULT_IP            ("127.0.0.1")           ///< default IP
#define PARAM_DEFAULT_PORT          (5050)                  ///< default port
#define PARAM_DEFAULT_SPORT         (0)                     ///< default sport
#define PARAM_DEFAULT_MODEL         ("mum")                 ///< default model type
#define PARAM_DEFAULT_CONNECT_NUM   (1)                     ///< default connection number
#define PARAM_DEFAULT_THREAD_NUM    (1)                     ///< default thread number
#define PARAM_DEFAULT_DOMAIN        ("tcp")                 ///< default communication domain
#define PARAM_DEFAULT_API           ("readwrite")           ///< default API type
#define PARAM_DEFAULT_PKTLEN        (1024)                  ///< default packet length of message
#define PARAM_DEFAULT_VERIFY        (false)                 ///< default flag of message verifying
#define PARAM_DEFAULT_DEBUG         (false)                 ///< default flag of debug
#define PARAM_DEFAULT_RINGPMD       (false)                 ///< default flag of ring PMD of dpdk
#define PARAM_DEFAULT_EPOLLCREATE   ("ec")                  ///< default method of epoll_create
#define PARAM_DEFAULT_ACCEPT        ("ac")                  ///< default method of accept method
#define PARAM_DEFAULT_GROUPIP       ("0.0.0.0")             ///< default group IP>


enum {
#define PARAM_NAME_AS               ("as")                  ///< name of parameter type
    PARAM_NUM_AS = 'a',
#define PARAM_NAME_IP               ("ip")                  ///< name of parameter IP
    PARAM_NUM_IP = 'i',
#define PARAM_NAME_PORT             ("port")                ///< name of parameter port
    PARAM_NUM_PORT = 'p',
#define PARAM_NAME_SPORT            ("sport")                ///< name of parameter sport
    PARAM_NUM_SPORT = 's',
#define PARAM_NAME_MODEL            ("model")               ///< name of parameter model type
    PARAM_NUM_MODEL = 'm',
#define PARAM_NAME_CONNECT_NUM      ("connectnum")          ///< name of parameter connection number
    PARAM_NUM_CONNECT_NUM = 'c',
#define PARAM_NAME_THREAD_NUM       ("threadnum")           ///< name of parameter thread number
    PARAM_NUM_THREAD_NUM = 't',
#define PARAM_NAME_DOMAIN           ("domain")              ///< name of parameter domain
    PARAM_NUM_DOMAIN = 'D',
#define PARAM_NAME_API              ("api")                 ///< name of parameter API type
    PARAM_NUM_API = 'A',
#define PARAM_NAME_PKTLEN           ("pktlen")              ///< name of parameter packet length of message
    PARAM_NUM_PKTLEN = 'P',
#define PARAM_NAME_VERIFY           ("verify")              ///< name of parameter flag of message verifying
    PARAM_NUM_VERIFY = 'v',
#define PARAM_NAME_RINGPMD          ("ringpmd")             ///< name of parameter flag of ring PMD of dpdk
    PARAM_NUM_RINGPMD = 'r',
#define PARAM_NAME_DEBUG            ("debug")               ///< name of parameter flag of debug
    PARAM_NUM_DEBUG = 'd',
#define PARAM_NAME_HELP             ("help")                ///< name of parameter help
    PARAM_NUM_HELP = 'h',
#define PARAM_NAME_EPOLLCREATE      ("epollcreate")         ///< name of parameter epollcreate
    PARAM_NUM_EPOLLCREATE = 'E',
#define PARAM_NAME_ACCEPT           ("accept")              ///< name of parameter accept
    PARAM_NUM_ACCEPT = 'C',
#define PARAM_NAME_GROUPIP          ("groupip")             ///< name of parameter group ip
    PARAM_NUM_GROUPIP = 'g',
};

#define NO_ARGUMENT             0                           ///< options takes no arguments
#define REQUIRED_ARGUMETN       1                           ///< options requires arguments
#define OPTIONAL_ARGUMETN       2                           ///< options arguments are optional


/**
 * @brief program option description
 * The program option description.
 */
struct ProgramOption {
    const char *name;       ///< name of program option
    int32_t has_arg;        ///< whether program option takes an argument, one of no, required, and optional
    int32_t *flag;          ///< if not `NULL`, set `*flag` to `val` when option found
    int32_t val;            ///< the number of this program option
};

/**
 * @brief porgram parameter
 * The porgram's parameters.
 */
struct ProgramParams {
    char*               as;                 ///< as server or client
    char*               ip;                 ///< IP address
    bool                port[UNIX_TCP_PORT_MAX];       ///< index:port list; value:port is set or not
    bool                sport[UNIX_TCP_PORT_MAX];       ///< index:sport list; value:sport is set or not
    char*               model;              ///< model type
    uint32_t            thread_num;         ///< the number of threads
    uint32_t            connect_num;        ///< the connection number
    char*               domain;             ///< the communication dimain
    char*               api;                ///< the type of api
    uint32_t            pktlen;             ///< the packet length
    bool                verify;             ///< if we verify the message or not
    bool                debug;              ///< if we print the debug information or not
    char*               epollcreate;        ///< epoll_create method
    char*               accept;             ///< accept connections method
    bool                ringpmd;            ///< if we use ring PMD or not
    char*               groupip;            ///< group IP address>
};

/**
 * @brief initialize the parameters
 * This function initializes the parameters of main function.
 * @param params        the parameters pointer
 */
void program_params_init(struct ProgramParams *params);

/**
 * @brief print help information
 * This function prints help informations.
 */
void program_params_help(void);

/**
 * @brief parse the parameters
 * This function parses the parameters of main function.
 * @param params        the parameters pointer
 * @param argc          the count of arguments
 * @param argv          the value of arguments
 * @return              the result flag
 */
int32_t program_params_parse(struct ProgramParams *params, uint32_t argc, char *argv[]);

/**
 * @brief print the parameters
 * This function prints the parameters of main function.
 * @param params        the parameters pointer
 */
void program_params_print(struct ProgramParams *params);


#endif // __EXAMPLES_PARAMETER_H__
