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

#include <sys/types.h>
#include <string.h>
#include <getopt.h>
#include <syslog.h>
#include <securec.h>

#include "ltran_log.h"
#include "ltran_base.h"
#include "ltran_param.h"

#define NO_ARGS             0
#define HAS_ARGS            1

#define GAZELLE_OPT_LONG_HELP "help"
#define GAZELLE_OPT_LONG_VERSION "version"
#define GAZELLE_OPT_LONG_CONFIG_FILE "config-file"

enum {
    GAZELLE_OPT_NUM_SHORT_HELP = 'h',
    GAZELLE_OPT_NUM_SHORT_VERSION = 'v',
    GAZELLE_OPT_NUM_SHORT_CONFIG_FILE = 'c'
};

static const struct option g_gazelle_long_options[] = {
    {GAZELLE_OPT_LONG_HELP, NO_ARGS, NULL, GAZELLE_OPT_NUM_SHORT_HELP},
    {GAZELLE_OPT_LONG_VERSION, NO_ARGS, NULL, GAZELLE_OPT_NUM_SHORT_VERSION},
    {GAZELLE_OPT_LONG_CONFIG_FILE, HAS_ARGS, NULL, GAZELLE_OPT_NUM_SHORT_CONFIG_FILE},
    {0, 0, NULL, 0}
};

static void show_version(void)
{
    printf(VER_FMT, VER_NAME);
}

static void show_usage(void)
{
    printf("Usage:\n"
        "ltran [OPTION]... [FILE] ...\n"
        "    -h, --help                     this usage. \n"
        "    -v, --version                  ltran version. \n"
        "    -c, --config-file <FILE>       config file will use. all parameters can be set in. \n");
}

static int32_t parse_cmd_args(int32_t argc, char *argv[], char *config_file)
{
    int32_t opt, ret;
    int32_t retVal;
    int32_t option_index = 0;

    // no param input by command, use default config file.
    if (argc == 1) {
        syslog(LOG_INFO, "Use default config file %s \n", config_file);
        return GAZELLE_OK;
    }

    optopt = 0;
    optind = 0;
    for (opt = getopt_long(argc, argv, "hvc:", g_gazelle_long_options, &option_index);
         opt != EOF;
         opt = getopt_long(argc, argv, "hvc:", g_gazelle_long_options, &option_index)) {
        switch (opt) {
            case GAZELLE_OPT_NUM_SHORT_HELP:
                show_usage();
                retVal = GAZELLE_QUIT;
                break;
            case GAZELLE_OPT_NUM_SHORT_VERSION:
                show_version();
                retVal = GAZELLE_QUIT;
                break;
            case GAZELLE_OPT_NUM_SHORT_CONFIG_FILE:
                if ((optarg == NULL) || (*optarg == '\0')) {
                    show_usage();
                    retVal = GAZELLE_QUIT;
                    break;
                }
                ret = strncpy_s(config_file, GAZELLE_PATH_BUFFER_SIZE, optarg, strlen(optarg) + 1);
                if (ret != EOK) {
                    syslog(LOG_ERR, "%s:%d strncpy_s fail ret=%d \n", __FUNCTION__, __LINE__, ret);
                }
                retVal = GAZELLE_OK;
                break;
            default:
                show_usage();
                retVal = GAZELLE_QUIT;
                break;
        }
        return retVal;
    }
    return GAZELLE_ERR;
}

int32_t ltran_config_init(int32_t argc, char *argv[])
{
    int32_t ret;

    char config_file_path[GAZELLE_PATH_BUFFER_SIZE] = DEFAULT_LTRAN_CONF_PATH;
    ret = parse_cmd_args(argc, argv, config_file_path);
    if (ret == GAZELLE_ERR) {
        syslog(LOG_ERR, "parse_cmd_args. ret: %d\n", ret);
        return GAZELLE_ERR;
    } else if (ret == GAZELLE_QUIT) {
        return GAZELLE_QUIT;
    }
    ret = parse_config_file_args(config_file_path, get_ltran_config());
    if (ret != GAZELLE_OK) {
        syslog(LOG_ERR, "parse config file args error. errno: %d\n", ret);
        return GAZELLE_ERR;
    }

    return GAZELLE_OK;
}

