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


#ifndef __PARAMETER_H__
#define __PARAMETER_H__


#include "utilities.h"


/**
 * @brief porgram parameter
 * The porgram's parameters.
 */
struct ProgramParams
{
    char*               as;                 ///< as server or client
    char*               ip;                 ///< IP address
    uint32_t            port;               ///< port
    char*               model;              ///< model type
    uint32_t            thread_num;         ///< the number of threads
    uint32_t            connect_num;        ///< the connection number
    char*               api;                ///< the type of api
    uint32_t            pktlen;             ///< the packet length
    bool                verify;             ///< if we verify the message or not
    bool                ringpmd;            ///< if we use ring PMD or not
};


/**
 * @brief initialize the parameters
 * This function initializes the parameters of main function. 
 * @param params        the parameters pointer
 */
void program_params_init(struct ProgramParams *params);

/**
 * @brief parse the parameters
 * This function parses the parameters of main function. 
 * @param params        the parameters pointer
 * @param argc          the count of arguments
 * @param argv          the value of arguments
 * @return              the result flag
 */
int32_t program_params_parse(struct ProgramParams *params, int argc, char *argv[]);

/**
 * @brief print the parameters
 * This function prints the parameters of main function. 
 * @param params        the parameters pointer
 */
void program_params_print(struct ProgramParams *params);


#endif // __PARAMETER_H__
