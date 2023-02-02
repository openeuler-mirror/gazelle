# Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
# gazelle is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

usage()
{
    echo "Usage: sh llt.sh [OPTIONS]"
    echo "Use llt.sh to control llt operation"
    echo
    echo "Misc:"
    echo "  -h, --help                      Print this help, then exit"
    echo
    echo "Compile Options:"
    echo "  -m, --cmake <option>            use cmake genenate Makefile, eg: -m(default), -mcoverage, -masan, --cmake, --cmake=coverage"
    echo "  -c, --compile                   Enable compile"
    echo "  -e, --empty                     Enable compile empty(make clean)"
    echo
    echo "TestRun Options"
    echo "  -r, --run-llt <option>          Run all llt, eg: -r, -rscreen(default), -rxml, --run-llt, --run-llt=screen, --run-llt=xml"
    echo "  -s, --specify-llt FILE          Only Run specify llt executable FILE, eg: -smain_llt, --specify-llt=main_llt"
    echo
    echo "Coverage Options"
    echo "  -t, --cover-report <option>     Enable coverage report. eg: -t, -thtml(default), -ttxt, --cover-report, --cover-report=html, --cover-report=txt"
    echo "  -f, --cover-file FILE           Specified FILE coverage report, eg: -fmain.c, --cover-file=main.c"
    echo
}

ARGS=`getopt -o "hcer::m::t::s:f:" -l "help,cmake::,empty,cover-report::,run-llt::,specify-llt:,cover-file:" -n "run_llt.sh" -- "$@"`
if [ $? != 0 ]; then
    usage
    exit 1
fi

eval set -- "${ARGS}"

if [ x"$ARGS" = x" --" ]; then
    #set default value
    COMPILE_ENABLE=no
    COVERAGE_ENABLE=no
    ASAN_ENABLE=no
    EMPTY_ENABLE=no
    RUN_LLT=yes
    RUN_MODE=screen #value: screen or xml
    COVER_REPORT_ENABLE=no
fi

while true; do
    case "${1}" in
        -m|--cmake)
            CMAKE_ENABLE=yes
            case "$2" in
                "") shift 2;;
                coverage) COVERAGE_ENABLE=yes; shift 2;;
                asan) ASAN_ENABLE=yes; shift 2;;
                *) echo "Error param: $2"; exit 1;;
            esac;;
        -h|--help)
            usage; exit 0;;
        -c|--compile)
            COMPILE_ENABLE=yes
            shift;;
        -e|--empty)
            EMPTY_ENABLE=yes
            shift;;
        -r|--run-llt)
            RUN_LLT=yes
            case "$2" in
                "") RUN_MODE=screen; shift 2;;
                screen) RUN_MODE=screen; shift 2;;
                xml) RUN_MODE=xml; shift 2;;
                *)echo "Error param: $2"; exit 1;;
            esac;;
        -t|--cover-report)
            COVER_REPORT_ENABLE=yes
            case "$2" in
                "") COVER_STYLE=html;shift 2;;
                html) COVER_STYLE=html;shift 2;;
                txt) COVER_STYLE=txt;shift 2;;
                *)echo "Error param: $2"; exit 1;;
            esac;;
        -s|--specify-llt)
            SPECIFY_CASES=$2
            shift 2;;
        -f|--cover-file)
            COVER_FILE=$2
            shift 2;;
        --)
            shift; break;;
    esac
done

function test_empty()
{
    echo ---------------------- llt empty begin ----------------------
    set -x
    echo "remove directory build"
    rm -rf build
    set +x
    echo ---------------------- llt empty end ------------------------
}

function test_cmake()
{
    local CMAKE_OPTION="-DCMAKE_BUILD_TYPE=Debug"

    echo ---------------------- llt cmake begin ----------------------
    if [ ! -d "build" ]; then
        mkdir build
    fi
    chmod 755 build
    cd build
    if [ x"${COVERAGE_ENABLE}" = x"yes" ]; then
        CMAKE_OPTION="${CMAKE_OPTION} -DCOVERAGE_ENABLE=1"
    fi

    if [ x"${ASAN_ENABLE}" = x"yes" ]; then
        CMAKE_OPTION="${CMAKE_OPTION} -DASAN_ENABLE=1"
    fi

    cmake .. ${CMAKE_OPTION}
    cd -
    echo ---------------------- llt cmake end ------------------------
    echo
}

function test_compile()
{
    echo ---------------------- llt compile begin ----------------------
    cd build
    make -j
    cd -
    echo ---------------------- llt compile end ------------------------
    echo
}

function test_run_all_test()
{
    ret=1
    echo ---------------------- llt run begin --------------------------
    if [ x"${RUN_MODE}" = x"screen" ]; then
        RUN_MODE=0
    elif [ x"${RUN_MODE}" = x"xml" ]; then
        RUN_MODE=1
    elif [ x"${RUN_MODE}" = x"" ]; then
        RUN_MODE=0
    else
        echo "not suport run mode <${RUN_MODE}>"
        usage
        exit 1
    fi

    cd build
    if [ x"${SPECIFY_CASES}" = x"" ]; then
        SPECIFY_CASES=`find -name "*_test"` # run all test
    else
        SPECIFY_CASES=`find -name "${SPECIFY_CASES}"`
    fi

    TEST_LOG=test_result.log
    >$TEST_LOG

    for TEST in $SPECIFY_CASES; do
        echo $TEST
        $TEST $RUN_MODE
        if [ $? != 0 ];then
            echo $TEST FAILED >> $TEST_LOG
            ret=1
        else
            echo $TEST success >> $TEST_LOG
            ret=0
        fi
    done
    echo ""
    echo '######################test result begin######################'
    cat $TEST_LOG
    echo '#######################test result end#######################'
    echo ""
    cd -
    echo ---------------------- llt run end --------------------------
    return $ret
}

function test_coverage()
{
    echo ------------------ llt generate coverage begin --------------
    cd build
    if [ x"${COVER_STYLE}" = x"txt" ]; then
        GCDAS=`find -name "${COVER_FILE}.gcda"`
        if [ x"$GCDAS" = x"" ]; then
            echo "not find ${COVER_FILE}.gcda"
            echo
            exit 1
        fi

        for GCDA in $GCDAS; do
            gcov $GCDA
        done

        find -name "*.h.gcov" | xargs rm -f
        echo '#################################'
        find -name "${COVER_FILE}.gcov"
        echo '#################################'
    elif [ x"${COVER_STYLE}" = x"html" ]; then
        if [ -d coverage ]; then
            rm -rf coverage
        fi
        mkdir coverage
        if [ x"${COVER_FILE}" = x"" ]; then
            LCOV_CMD="-d ./"
        else
            GCDAS=`find -name "${COVER_FILE}.gcda"`
            if [ $? != 0 ]; then
                echo "not match ${COVER_FILE}.gcda"
                exit 1
            fi

            for GCDA in ${GCDAS}; do
                TMP_STR=" -d ${GCDA}";
                LCOV_CMD="${LCOV_CMD} ${TMP_STR}";
            done
        fi

        lcov -c -d . -o coverage/coverage.info --exclude "/usr/*" --exclude "*stub*" --exclude "*test*" --exclude "libnet_dfx_msg.c" --rc lcov_branch_coverage=1  --ignore-errors gcov --ignore-errors source --ignore-errors graph
        if [ $? != 0 ]; then
            echo "lcov generate coverage.info fail."
            exit 1
        fi

        genhtml coverage/coverage.info -o coverage/html --branch-coverage --rc lcov_branch_coverage=1 -s --legend --ignore-errors source
        if [ $? != 0 ]; then
            echo "genhtml fail."
            exit 1
        fi
        chmod 755 -R coverage
    fi
    cd -
    echo ------------------ llt generate coverage end ----------------
}

exit_ret=0

starttime=`date +'%Y-%m-%d %H:%M:%S'`
sed -i "s/^static int32_t parse_conf_file/int32_t parse_conf_file/" ../../src/lstack/core/lstack_cfg.c
sed -i "s/^    get_protocol_stack_group/    \/\/get_protocol_stack_group/" ../../src/lstack/core/lstack_cfg.c
sed -i "/int32_t init_stack_numa_cpuset/i\    #if 0" ../../src/lstack/core/lstack_cfg.c
sed -i "/static int32_t gazelle_parse_base_virtaddr/i\    #endif" ../../src/lstack/core/lstack_cfg.c
if [ x"${EMPTY_ENABLE}" = x"yes" ]; then
    test_empty
fi

if [ x"${CMAKE_ENABLE}" = x"yes" ]; then
    test_cmake
fi

if [ x"${COMPILE_ENABLE}" = x"yes" ]; then
    test_compile
fi

if [ x"${RUN_LLT}" = x"yes" ]; then
    test_run_all_test
    exit_val=$?
fi

if [ x"${COVER_REPORT_ENABLE}" = x"yes" ]; then
    test_coverage
fi
git checkout HEAD -- ../../src/lstack/core/lstack_cfg.c

endtime=`date +'%Y-%m-%d %H:%M:%S'`
start_seconds=$(date --date="$starttime" +%s);
end_seconds=$(date --date="$endtime" +%s);
echo "Running time： "$((end_seconds-start_seconds))"s"
exit $exit_val
