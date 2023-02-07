#! /bin/bash

#set -xe

usage()
{
    echo "Usage: sh test.sh [OPTIONS]"
    echo "Use test.sh to control integration test operation"
    echo
    echo "Misc:"
    echo "  -h, --help                      Print this help, then exit"
    echo
    echo "Compile Options:"
    echo "  -m, --cmake <option>            use cmake genenate Makefile, eg: -m(default), -mcoverage, --cmake, --cmake=coverage"
    echo "  -c, --compile                   Enable compile"
    echo "  -e, --empty                     Enable compile empty(make clean)"
    echo
    echo "TestRun Options"
    echo "  -r, --run-test <option>         Run all test, eg: -r, -rscreen(default), -rxml, --run-test, --run-test=screen, --run-test=xml"
    echo "  -s, --specify-test FILE         Only Run specify test executable FILE, eg: -smain_test, --specify-test=main_test"
    echo
    echo "Coverage Options"
    echo "  -t, --cover-report <option>     Enable coverage report. eg: -t, -thtml(default), -ttxt, --cover-report, --cover-report=html, --cover-report=txt"
    echo "  -f, --cover-file FILE           Specified FILE coverage report, eg: -fmain.c, --cover-file=main.c"
    echo
    echo "IP Options"
    echo "  -i, --ip <option>               Modify default ip. eg: -i, -i 192.168.1.8(default), --ip, --ip=192.168.1.8"
    echo
}

ARGS=`getopt -o "hcer::m::t::s:f:i:" -l "help,cmake::,empty,cover-report::,run-test::,specify-test:,cover-file:,ip:" -n "test.sh" -- "$@"`
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
    RUN_TEST=yes
    RUN_MODE=screen #value: screen or xml
    COVER_REPORT_ENABLE=no
    MODIFY_DEFAULT_IP=no
fi

while true; do
    case "${1}" in
        -h|--help)
            usage; exit 0;;
        -m|--cmake)
            CMAKE_ENABLE=yes
            case "$2" in
                "") shift 2;;
                coverage) COVERAGE_ENABLE=yes; shift 2;;
                asan) ASAN_ENABLE=yes; shift 2;;
                *) echo "Error param: $2"; exit 1;;
            esac;;
        -c|--compile)
            COMPILE_ENABLE=yes
            shift;;
        -e|--empty)
            EMPTY_ENABLE=yes
            shift;;
        -r|--run-test)
            RUN_TEST=yes
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
        -s|--specify-test)
            SPECIFY_TEST=$2
            shift 2;;
        -f|--cover-file)
            COVER_FILE=$2
            shift 2;;
        -i|--ip)
            MODIFY_DEFAULT_IP=yes
            TEST_IP=$2
            shift 2;;
        --)
            shift; break;;
    esac
done

function modify_test_ip()
{
    echo ---------------------- test modify test ip begin ----------------------
    set -x
    sed -i "/host_addr=/chost_addr=\"${TEST_IP}\"" /etc/gazelle/lstack.conf
    sed -i "/host_addr=/chost_addr=\"${TEST_IP}\"" test_gazellectl/config/lstack.conf
    sed -i "/host_addr=/chost_addr=\"${TEST_IP}\"" test_lstack/config/lstack.conf
    sed -i "/host_addr=/chost_addr=\"${TEST_IP}\"" test_wrap/config/lstack.conf
    sed -i "/^CnHostName=/cCnHostName=${TEST_IP}"   /etc/gazelle/config.ini
    set +x
    echo ---------------------- test modify test ip end ------------------------
}

function test_empty()
{
    echo ---------------------- test empty begin ----------------------
    set -x
    echo "remove directory build"
    rm -rf build
    set +x
    echo ---------------------- test empty end ------------------------
}

function test_cmake()
{
    local CMAKE_OPTION="-DCMAKE_BUILD_TYPE=Debug"

    echo ---------------------- test cmake begin ----------------------
    if [ ! -d "/opt/libos" ]; then
        mkdir /opt/libos
    fi
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
    echo ---------------------- test cmake end ------------------------
    echo
}

function test_compile()
{
    echo ---------------------- test compile begin ----------------------
    # compile gazelle coverage version
    cur_dir=`pwd`
    cd ../../
    export GAZELLE_COVERAGE_ENABLE=1
    cp -fr src/ltran/main.c src/ltran/main.bak
    cp -fr src/lstack/api/lstack_signal.c src/lstack/api/lstack_signal.bak
    cp -fr src/ltran/ltran_forward.c src/ltran/ltran_forward.bak
    sed -i 's/__rte_always_inline/ /g' src/ltran/ltran_forward.c
    sed -i '/kill/cexit(0);' src/ltran/main.c
    sed -i '/kill/cexit(0);' src/lstack/api/lstack_signal.c
    rm -fr /lib64/liblstack.* /usr/bin/gazellectl /usr/bin/ltran
    cd build
    sh build.sh
    cd -
    cp -fr src/ltran/main.bak src/ltran/main.c
    cp -fr src/lstack/api/lstack_signal.bak src/lstack/api/lstack_signal.c
    # install gazelle coverage version
    install -Dpm 0755 src/lstack/liblstack.*     /lib64/
    install -Dpm 0644 src/lstack/lstack.Makefile /etc/gazelle
    install -Dpm 0644 src/lstack/lstack.conf     /etc/gazelle

    install -Dpm 0755 src/ltran/gazellectl       /usr/bin
    install -Dpm 0755 src/ltran/ltran            /usr/bin
    install -Dpm 0644 src/ltran/ltran.conf       /etc/gazelle
    unset GAZELLE_COVERAGE_ENABLE
    mv src/ltran/main.bak src/ltran/main.c
    mv src/lstack/api/lstack_signal.bak src/lstack/api/lstack_signal.c
    mv src/ltran/ltran_forward.bak src/ltran/ltran_forward.c
    cd $cur_dir

    # compile gazelle test cases
    cd build
    make -j
    cd -

    echo ---------------------- test compile end ------------------------
    echo
}

function test_run_all_test()
{
    ret=1
    echo ---------------------- test run begin --------------------------
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
    if [ x"${SPECIFY_TEST}" = x"" ]; then
        SPECIFY_TEST=`find -name "*_test"` # run all test
    else
        SPECIFY_TEST=`find -name "${SPECIFY_TEST}"`
    fi

    export LD_LIBRARY_PATH=`pwd`
    export LD_PRELOAD=libsignal_hijack.so

    TEST_LOG=test_result.log
    >$TEST_LOG

    for TEST in $SPECIFY_TEST; do
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

    unset LD_LIBRARY_PATH
    unset LD_PRELOAD
    cd -
    echo ---------------------- test run end --------------------------
    return $ret
}

function test_coverage()
{
    echo ------------------ test generate coverage begin --------------
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

        lcov -c -d ../../../src/ -o coverage/coverage.info --exclude "/usr/*" --exclude "*dpdk*" --rc lcov_branch_coverage=1  --ignore-errors gcov --ignore-errors source --ignore-errors graph
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
    echo ------------------ test generate coverage end ----------------
}

exit_ret=0

starttime=`date +'%Y-%m-%d %H:%M:%S'`
if [ x"${EMPTY_ENABLE}" = x"yes" ]; then
    test_empty
fi

if [ x"${CMAKE_ENABLE}" = x"yes" ]; then
    test_cmake
fi

if [ x"${COMPILE_ENABLE}" = x"yes" ]; then
    test_compile
fi

if [ x"${MODIFY_DEFAULT_IP}" = x"yes" ]; then
    modify_test_ip
fi

if [ x"${RUN_TEST}" = x"yes" ]; then
    test_run_all_test
    exit_val=$?
fi

if [ x"${COVER_REPORT_ENABLE}" = x"yes" ]; then
    test_coverage
fi
endtime=`date +'%Y-%m-%d %H:%M:%S'`
start_seconds=$(date --date="$starttime" +%s);
end_seconds=$(date --date="$endtime" +%s);
echo "Running time： "$((end_seconds-start_seconds))"s"
exit $exit_val
#set +x
