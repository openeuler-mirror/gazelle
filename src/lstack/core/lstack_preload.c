/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* gazelle is licensed under the Mulan PSL v2.
* You can use this software according to the terms and conditions of the Mulan PSL v2.
* You may obtain a copy of Mulan PSL v2 at:
*     http://license.coscl.org.cn/MulanPSL2
* THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
* PURPOSE.
* See the Mulan PSL v2 for more details.
*/
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "lstack_preload.h"

#define LSTACK_PRELOAD_ENV_SYS      "LD_PRELOAD"
#define LSTACK_SO_NAME              "liblstack.so"
#define LSTACK_PRELOAD_NAME_LEN     PATH_MAX
#define LSTACK_PRELOAD_ENV_PROC     "GAZELLE_BIND_PROCNAME"

struct lstack_preload {
    int32_t preload_switch;
    char env_procname[LSTACK_PRELOAD_NAME_LEN];
};
static struct lstack_preload g_preload_info = {0};

static int32_t preload_check_bind_proc(void)
{
    char proc_path[PATH_MAX] = {0};

    if (!g_preload_info.preload_switch) {
        return 0;
    }

    if (readlink("/proc/self/exe", proc_path, PATH_MAX - 1) <= 0) {
        return -1;
    }

    char *proc_name = strrchr(proc_path, '/');
    if (!proc_name) {
        return -1;
    }

    if (strncmp(++proc_name, g_preload_info.env_procname, PATH_MAX) == 0) {
        return 0;
    }
    return -1;
}

static int32_t preload_info_init(void)
{
    char *enval = NULL;

    g_preload_info.preload_switch = 0;

    enval = getenv(LSTACK_PRELOAD_ENV_SYS);
    if (enval == NULL) {
        return 0;
    }

    if (strstr(enval, LSTACK_SO_NAME) == NULL) {
        return 0;
    }

    enval = getenv(LSTACK_PRELOAD_ENV_PROC);
    if (enval == NULL) {
        return -1;
    }
    if (strcpy_s(g_preload_info.env_procname, LSTACK_PRELOAD_NAME_LEN, enval) != EOK) {
        return -1;
    }

    g_preload_info.preload_switch = 1;
    LSTACK_PRE_LOG(LSTACK_INFO, "LD_PRELOAD ok\n");
    return preload_check_bind_proc();
}
