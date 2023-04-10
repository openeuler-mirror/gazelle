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
export CURRENT_PATH=$(dirname $(readlink -f ${BASH_SOURCE[0]}))
cd $CURRENT_PATH

make -C ../src/lstack clean
make -C ../src/lstack
if [ $? -ne 0 ]; then
    echo "build lstack failed"
    exit 1
fi

cd ../src/ltran
rm -f CMakeCache.txt
rm -f ltran gazellectl
rm -rf CMakeFiles
cmake .
make
if [ $? -ne 0 ]; then
    echo "build ltran failed"
    exit 1
fi

cd -
