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


#include "utilities.h"
#include "parameter.h"
#include "server.h"
#include "client.h"


static struct ProgramParams prog_params;


int32_t main(int argc, char *argv[])
{
    int32_t ret = PROGRAM_OK;

    program_params_init(&prog_params);
    ret = program_params_parse(&prog_params, argc, argv);
    if (ret == PROGRAM_ABORT) {
        return ret;
    }
    program_params_print(&prog_params);

    if (strcmp(prog_params.as, "server") == 0) {
        server_create(&prog_params);
    } else {
        client_create(&prog_params);
    }

    return ret;
}
