#!/bin/bash
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
# gazelle is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

 
function generate_coverage()
{
        local target_dir=$(dirname `pwd`)
        echo ------------------ generate coverage begin --------------
        if [ -d ${target_dir}/build/coverage/html ]; then
            rm -rf ${target_dir}/build/coverage/html
        fi
        mkdir -p ${target_dir}/build/coverage/html
        if [ x"${COVER_FILE}" = x"" ]; then
            LCOV_CMD="-d ${target_dir}"
        else
            GCDAS=`find ${target_dir} -name "${COVER_FILE}.gcda"`
            if [ $? != 0 ]; then
                echo -e "\033[;31mnot find\033[0m ${COVER_FILE}.gcda"
                exit  1
            fi

            for GCDA in ${GCDAS}; do
                TMP_STR=" -d ${GCDA}";
                LCOV_CMD="${LCOV_CMD} ${TMP_STR}";
            done
        fi

        # lcov -c ${LCOV_CMD} -o ${target_dir}/build/coverage/html/coverage.info --exclude '*_test.c' --include '*.c' --include '*.cpp' --include '*.cc' --rc lcov_branch_coverage=1 --ignore-errors gcov --ignore-errors source --ignore-errors graph
        lcov -c ${LCOV_CMD} -b $(dirname $(pwd)) --exclude '*test*' --exclude '*.h' -o ${target_dir}/build/coverage/html/coverage.info --rc lcov_branch_coverage=1 --ignore-errors gcov --ignore-errors source --ignore-errors graph
        if [ $? != 0 ]; then
            echo -e "lcov generate coverage.info \033[;31mfail\033[0m."
            exit 1
        fi

        genhtml ${target_dir}/build/coverage/html/coverage.info -o ${target_dir}/build/coverage/html --branch-coverage --rc lcov_branch_coverage=1 -s --legend --ignore-errors source
        if [ $? != 0 ]; then
            echo -e "genhtml \033[;31mfail\033[0m."
            exit 1
        fi
        chmod 755 -R ${target_dir}/build/coverage/html
        echo ------------------ generate coverage end ----------------
}

LIB_FUZZING_ENGINE="/lib64/libFuzzer.a"
FUZZ_OPTION="../corpus -dict=../fuzz.dict -runs=30000000 -max_total_time=10800 -artifact_prefix=fuzz-"

if [ ! -f $LIB_FUZZING_ENGINE ]; then
    echo "$LIB_FUZZING_ENGINE not exist, pls check"
    exit 1
fi

rm -rf build
mkdir build
cd build

sed 's/ read(/ s_read(/' -i ../../../src/lstack/api/lstack_wrap.c
sed 's/ write/ s_write/' -i ../../../src/lstack/api/lstack_wrap.c
sed 's/ fcntl(/ s_fcntl(/' -i ../../../src/lstack/api/lstack_wrap.c
sed 's/ socket(/ s_socket(/' -i ../../../src/lstack/api/lstack_wrap.c
sed 's/ close(/ s_close(/' -i ../../../src/lstack/api/lstack_wrap.c
sed 's/ write(/ s_write(/' -i ../../../src/lstack/api/lstack_wrap.c
sed 's/ send(/ s_send(/' -i ../../../src/lstack/api/lstack_wrap.c
sed 's/ sendmsg(/ s_sendmsg(/' -i ../../../src/lstack/api/lstack_wrap.c

cmake ..
make -j

export ASAN_OPTIONS=halt_on_error=0

usage()
{
    echo "Usage: fuzz.sh [ltran_config | lstack_config | lstack_api]"
}

case "$1" in
    ltran_config)
        ./ltran_config_fuzz $FUZZ_OPTION;;
    lstack_config)
        ./lstack_config_fuzz $FUZZ_OPTION;;
    lstack_api)
        ./lstack_api_fuzz $FUZZ_OPTION;;
    *)
        echo "param is wrong"
        usage; exit 0;;
esac

# 运行fuzz测试程序

# 查找crash文件
echo "############# Fuzz Result #############"
crash=`find -name "*-crash-*"`
if [ x"$crash" != x"" ]; then
    echo "find bugs while fuzzing, pls check <*-crash-*> file"
    find -name "*-crash-*"
    echo "fuzz failed"
else
    echo "all fuzz success."
fi

generate_coverage

sed 's/ s_read/ read/' -i ../../../src/lstack/api/lstack_wrap.c
sed 's/ s_write/ write/' -i ../../../src/lstack/api/lstack_wrap.c
sed 's/ s_fcntl(/ fcntl(/' -i ../../../src/lstack/api/lstack_wrap.c
sed 's/ s_socket(/ socket(/' -i ../../../src/lstack/api/lstack_wrap.c
sed 's/ s_close(/ close(/' -i ../../../src/lstack/api/lstack_wrap.c
sed 's/ s_write(/ write(/' -i ../../../src/lstack/api/lstack_wrap.c
sed 's/ s_send(/ send(/' -i ../../../src/lstack/api/lstack_wrap.c
sed 's/ s_sendmsg(/ sendmsg(/' -i ../../../src/lstack/api/lstack_wrap.c
