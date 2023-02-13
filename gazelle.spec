%define conf_path %{_sysconfdir}/%{name}

Name:          gazelle
Version:       1.0.1
Release:       50
Summary:       gazelle is a high performance user-mode stack
License:       MulanPSL-2.0
URL:           https://gitee.com/openeuler/gazelle
Source0:       %{name}-%{version}.tar.gz

BuildRequires: cmake gcc-c++ lwip
BuildRequires: dpdk-devel >= 19.11
BuildRequires: numactl-devel libpcap-devel libconfig-devel libboundscheck

Requires:      dpdk >= 19.11
Requires:      numactl libpcap libconfig libboundscheck

Patch9001:     0001-fix-compile-error-unuse-result.patch
Patch9002:     0002-reduce-copy-in-send.patch
Patch9003:     0003-execute-gazelle_init_sock-before-read-event.patch
Patch9004:     0004-recvmsg-sendmsg-should-use-recvmsg_from_stack-sendms.patch
Patch9005:     0005-fix-LD_PRELOAD.patch
Patch9006:     0006-reduce-replenish-send_idle_ring-rpc-call.patch
Patch9007:     0007-parse_host_addr-should-be-executed-before-parse_dpdk.patch
Patch9008:     0008-fix-gazellectl-l-option-error.patch
Patch9009:     0009-bind-cpu-fail-just-walrm.patch
Patch9010:     0010-mfix-close-not-release-sock.patch
Patch9011:     0011-fix-evetns-err.patch
Patch9012:     0012-fix-dfx-info-show.patch
Patch9013:     0013-balance-acept.patch
Patch9014:     0014-fix-miss-evetn.patch
Patch9015:     0015-fix-too-much-evetns.patch
Patch9016:     0016-fix-dead-loop.patch
Patch9017:     0017-remove-unuse-event.patch
Patch9018:     0018-fix-gazellectl-show.patch
Patch9019:     0019-fix-repeate-msg.patch
Patch9020:     0020-fix-wakeup-typos.patch
Patch9021:     0021-fix-pasre-numacpulist.patch
Patch9022:     0022-fix-get-data-error.patch
Patch9023:     0023-delete-numa-bind-param.patch
Patch9024:     0024-refactor-event.patch
Patch9025:     0025-fix-event-miss.patch
Patch9026:     0026-get-fin-notice-app.patch
Patch9027:     0027-fix-parse-config.patch
Patch9028:     0028-fix-lstack-show-latency.patch
Patch9029:     0029-fix-code-check.patch
Patch9030:     0030-fix-accept-init-sock-faile.patch
Patch9031:     0031-fix-reuse-ip-listen-event-don-t-notice.patch
Patch9032:     0032-modify-readme-to-add-constraint.patch
Patch9033:     0033-fix-accept-check-remain-conn.patch
Patch9034:     0034-fix-wakeup-list-dead-loop.patch
Patch9035:     0035-add-check-for-stack-params.patch
Patch9036:     0036-the-sending-of-sock-last-data-is-triggered-by-lstack.patch
Patch9037:     0037-add-gazellectl-lstack-constraint.patch
Patch9038:     0038-refactor-event.patch
Patch9039:     0039-update-license-lockless-queue.patch
Patch9040:     0040-adapt-to-gazelle.patch
Patch9041:     0041-modify-securec-to-boundscheck.patch
Patch9042:     0042-fix-sock-invalid-address.patch
Patch9043:     0043-exit-lstack-process-after-ltran-instance-logout.patch
Patch9044:     0044-use-atomic-variales-to-count.patch
Patch9045:     0045-re-arrange-the-program-to-invoke-rte_eth_dev_start-b.patch
Patch9046:     0046-delete-redundant-file.patch
Patch9047:     0047-lstack-all-exit-move-to-init.patch
Patch9048:     0048-clean-code-fix-huge-func.patch
Patch9049:     0049-add-kernel-path-in-epoll-funcs.patch
Patch9050:     0050-refactor-kernel-event-poll-epoll.patch
Patch9051:     0051-post-thread_phase1-sem-to-avoid-block-main-thread-wh.patch
Patch9052:     0052-adjust-the-number-of-RX-TX-mbufs-of-each-stack-threa.patch
Patch9053:     0053-modify-README.patch
Patch9054:     0054-bugfix-https-gitee.com-src-openeuler-gazelle-issues-.patch
Patch9055:     0055-update-README.md.patch
Patch9056:     0056-ltran-fix-use-after-free-issue.patch
Patch9057:     0057-refactor-pkt-read-send-performance.patch
Patch9058:     0058-ltran-support-checksum.patch
Patch9059:     0059-add-examples-readme-compile-components-main-file-and.patch
Patch9060:     0060-add-examples-parameter-parsing.patch
Patch9061:     0061-lstack-core-fix-reta_conf-array-size-calculation.patch
Patch9062:     0062-Replace-gettid-with-rte_gettid.patch
Patch9063:     0063-modify-the-code-for-canonical-and-update-the-cmake-b.patch
Patch9064:     0064-enable-secure-compile-and-open-compile-log.patch
Patch9065:     0065-support-epoll-et-trig-mode.patch
Patch9066:     0066-lstack-support-low-power.patch
Patch9067:     0067-add-port-mask-range-check.patch
Patch9068:     0068-release-kni-device.patch
Patch9069:     0069-optimize-check-ltran-exist.patch
Patch9070:     0070-clean-code.patch
Patch9071:     0071-clean-code.patch
Patch9072:     0072-Support-build-gazelle-with-clang.patch
Patch9073:     0073-Allow-dynamic-load-PMDs.patch
Patch9074:     0074-resolve-patch-conflicts.patch
Patch9075:     0075-support-epoll-oneshot.patch
Patch9076:     0076-clean-code-space-before-operator.patch
Patch9077:     0077-ltran-support-muti-proc-with-same-ip.patch
Patch9078:     0078-fix-rpc-msg-out-of-bound.patch
Patch9079:     0079-fix-traversal-array-use-NULL-pointer.patch
Patch9080:     0080-same-stack-thread-don-t-repeate-send-msg.patch
Patch9081:     0081-modify-huge-dir-dir-name.patch
Patch9082:     0082-fix-memcpy-out-bounds.patch
Patch9083:     0083-fix-miss-send-rpc-msg-err.patch
Patch9084:     0084-fix-proc-can-not-exit-due-to-lack-of-mem-startup-fai.patch
Patch9085:     0085-read-data-with-err-event.patch
Patch9086:     0086-del-gazelle-ring-cons.tail-atomic-protect.patch
Patch9087:     0087-fix-send-return-vale.patch
Patch9088:     0088-add-examples.patch
Patch9089:     0089-expand-thread-rpc-msg-pool-size.patch
Patch9090:     0090-fix-ltran-sig_default_handler-kill-pid.patch
Patch9091:     0091-fix-fd-leak.patch
Patch9092:     0092-fix-del-conn-use-after-free.patch
Patch9093:     0093-init-g_gazelle_errno-before-use.patch
Patch9094:     0094-code-format-specification.patch
Patch9095:     0095-fix-gazelle-kernel-event-thread-affinity-same-with-s.patch
Patch9096:     0096-have_corelist_arg.patch
Patch9097:     0097-ltran-update-list.patch
Patch9098:     0098-remove-get_reg_ring_free_count.patch
Patch9099:     0099-add-errorno-EISCONN.patch
Patch9100:     0100-fix-sendmsg-data-write-wrong.patch
Patch9101:     0101-lstack-restore-pci-bus-after-init.patch
Patch9102:     0102-fix-malloc-rpc-msg-fail.patch
Patch9103:     0103-support-dpdk-dynamic-memory.patch
Patch9104:     0104-fix-lwip_send-fail-free-pbuf-miss-data.patch
Patch9105:     0105-merger-wakeup.patch
Patch9106:     0106-conenct-support-multi-queues.patch
Patch9107:     0107-merge-sendmsg-write.patch
Patch9108:     0108-add-thread-select-path.patch
Patch9109:     0109-support-conf-control-app-bind-numa.patch
Patch9110:     0110-fix-epoll_wait-cover-kernel-event.patch
Patch9111:     0111-fix-read-stack-data-return-0-when-no-data.patch
Patch9112:     0112-fix-stack-wakeup-node-del.patch
Patch9113:     0113-avoid-useless-stack-check-wakeup-event.patch
Patch9114:     0114-fix-mesg-loss.patch
Patch9115:     0115-add-accept4-and-epoll_create1.patch
Patch9116:     0116-refactor-event-notice.patch
Patch9117:     0117-add-writev-and-readv.patch
Patch9118:     0118-optimized-some-function-in-lstack.patch
Patch9119:     0119-fix-gazellectl-stats-err-when-donot-bind-numa.patch
Patch9120:     0120-add-usleep-when-write_ring-is-busy.patch
Patch9121:     0121-optimize-variable-access.patch
Patch9122:     0122-add-gro.patch
Patch9123:     0123-expand-nic-rx-desc-size.patch
Patch9124:     0124-add-kni-local-support-in-lstack.patch
Patch9125:     0125-resolve-the-conflict-between-the-eth_dev_ops-variabl.patch
Patch9126:     0126-add-pdump-support-in-lstack.patch
Patch9127:     0127-fix-uninit-stack-port_id-when-use-mutil-NIC.patch
Patch9128:     0128-fix-memleak-in-dpdk_ethdev_init-unlikely-path.patch
Patch9129:     0129-fix-epoll_wait-return-when-timeout-is-0.patch
Patch9130:     0130-fix-gazelle-pdump-init-fail-with-dpdk-21.11.patch
Patch9131:     0131-fix-add-outdated-event.patch
Patch9132:     0132-revert-write-usleep.patch
Patch9133:     0133-reduce-thread-variable-access.patch
Patch9134:     0134-add-readv-and-readv-kernel.patch
Patch9135:     0135-add-unlock-before-after.patch
Patch9136:     0136-add-mutil-NIC-support-in-gazelle.patch
Patch9137:     0137-remove-filename_check-in-gazellectl-to-fix-build-err.patch
Patch9138:     0138-cancel-kernel-sock-epoll-ctl-when-lwip-sock-connect.patch
Patch9139:     0139-modify-readv-and-writev-first-buf-is-null.patch
Patch9140:     0140-fix-pdump-and-mutil-NIC-init-fail.patch
Patch9141:     0141-modify-duplicate-code.patch
Patch9142:     0142-merge-lstack-rx-tx-mbuf-pool.patch
Patch9143:     0143-avoid-send-stop-when-mbuf-pool-empty.patch
Patch9144:     0144-fix-pcb-snd_buf-flip.patch
Patch9145:     0145-fix-lwip-send-return-0-add-err-event.patch
Patch9146:     0146-fix-data-flow-error-when-use-NIC-in-kernel.patch
Patch9147:     0147-fix-write-event-error.patch
Patch9148:     0148-add-malloc-init-zero.patch
Patch9149:     0149-modify-event-error.patch
Patch9150:     0150-add-unix_prefix-in-gazellectl.patch
Patch9151:     0151-fix-epoll_wait-report-event0.patch
Patch9152:     0152-add-TSO.patch
Patch9153:     0153-optimize-app-thread-write-buff-block.patch
Patch9154:     0154-expand-rxtx-mbuf-pool.patch
Patch9155:     0155-add-pdump-support-in-ltran.patch
Patch9156:     0156-dfx-gazellectl-add-pcb-wins-info.patch
Patch9157:     0157-fix-genarate-out-event-untimely.patch
Patch9158:     0158-rxtx-mbuf-pool-size-config-by-conf.patch
Patch9159:     0159-fix-kernel-event-thread-bind-numa-failed.patch
Patch9160:     0160-stack-thread-parms-config-by-conf.patch
Patch9161:     0161-ltran-rxtx-mbuf-pool-size-config-by-conf.patch
Patch9162:     0162-move-select_thread_path-after-posix_api_init.patch
Patch9163:     0163-add-RXTX_NB_MBUF_MAX-to-limit-mbuf_pool_size-to-its-.patch
Patch9164:     0164-stack-thread-params-default-val.patch
Patch9165:     0165-optimite-net-type.patch
Patch9166:     0166-app-bind-numa-when-epoll-poll-create.patch
Patch9167:     0167-remove-mbuf-reserve-in-mbuf-alloc.patch
Patch9168:     0168-pkts-bulk-send-to-nic.patch
Patch9169:     0169-rpc-dont-send.patch
Patch9170:     0170-recv-pbuf-free-timely.patch
Patch9171:     0171-optimite-send-pkts-dul-index.patch
Patch9172:     0172-expand-data-recv-buff.patch
Patch9173:     0173-dfx-add-mempool-count-info.patch
Patch9174:     0174-write-support-without-epoll-poll.patch
Patch9175:     0175-add-rcv-nxt-dfx-info.patch
Patch9176:     0176-mbuf-private-data-size-align-cache-line.patch
Patch9177:     0177-fix-send-pkts-bluk-err.patch
Patch9178:     0178-free-recv-pkts-bluks.patch
Patch9179:     0179-fix-lstack-Makefile-warning.patch
Patch9180:     0180-fix-null-pointer-deref-in-stack_broadcast_close.patch
Patch9181:     0181-pbuf-align-cache-line.patch
Patch9182:     0182-support-set-main-thread-affinity.patch
Patch9183:     0183-reduce-epoll-wakeup.patch
Patch9184:     0184-revert-expand-recv-data-buff.patch
Patch9185:     0185-add-the-suggestion-of-using-the-u-parameter-when-the.patch
Patch9186:     0186-move-control_client_thread-creation-after-control_in.patch
Patch9187:     0187-add-ret-check-in-pthread_create-and-fix-example-bug.patch
Patch9188:     0188-add-log-message-when-wait-for-connecting-to-ltran.patch
Patch9189:     0189-add-gazelle-fuzz.patch
Patch9190:     0190-add-unitest.patch
Patch9191:     0191-add-gazelle-setup-tools.patch
Patch9192:     0192-test-readv-writev-epoll_create1-accept4.patch
Patch9193:     0193-add-fucntest.patch
Patch9194:     0194-fix-coredump-in-example-server-mum-mode.patch
Patch9195:     0195-bring-up-kni-when-init.patch
Patch9196:     0196-change-mbuf_pool_size-in-lstack.conf-to-tcp_conn_cou.patch
Patch9197:     0197-fix-build-error-in-lstack.patch

%description
%{name} is a high performance user-mode stack.

ExclusiveArch: x86_64 aarch64

%prep
%autosetup -n %{name}-%{version} -p1

%build
cd %{_builddir}/%{name}-%{version}
# Add compile option, ignore map address check. Scenarios: asan test
%if 0%{?gazelle_map_addr_nocheck}
    sed -i 's/-pthread/-pthread -D gazelle_map_addr_nocheck/' %{_builddir}/%{name}-%{version}/src/ltran/CMakeLists.txt
%endif
sh build/build.sh

%install
install -dpm 0755 %{buildroot}/%{_bindir}
install -dpm 0755 %{buildroot}/%{_prefix}/lib64
install -dpm 0750 %{buildroot}/%{conf_path}

install -Dpm 0500 %{_builddir}/%{name}-%{version}/src/lstack/liblstack.*     %{buildroot}/%{_libdir}/
install -Dpm 0640 %{_builddir}/%{name}-%{version}/src/lstack/lstack.Makefile %{buildroot}/%{conf_path}/
install -Dpm 0640 %{_builddir}/%{name}-%{version}/src/lstack/lstack.conf     %{buildroot}/%{conf_path}/

install -Dpm 0500 %{_builddir}/%{name}-%{version}/src/ltran/gazellectl       %{buildroot}/%{_bindir}/
install -Dpm 0500 %{_builddir}/%{name}-%{version}/src/ltran/ltran            %{buildroot}/%{_bindir}/
install -Dpm 0640 %{_builddir}/%{name}-%{version}/src/ltran/ltran.conf       %{buildroot}/%{conf_path}/

%files
%defattr(-,root,root)
%dir %{conf_path}
%{_bindir}/*
%{_libdir}/liblstack.*
%{conf_path}/lstack.Makefile
%config(noreplace) %{conf_path}/lstack.conf
%config(noreplace) %{conf_path}/ltran.conf

%changelog
* Mon Feb 13 2023 net <jiangheng14@huawei.com> - 1.0.1-50
- change mbuf_pool_size in lstack.conf to tcp_conn_count * mbuf_count_per_conn
- bring up kni when init
- fix coredump in example server mum mode
- add fucntest
- test readv writev epoll_create1 accept4

* Mon Feb 6 2023 jiangheng12 <jiangheng14@huawei.com> - 1.0.1-49
- add gazelle setup tools
- add unitest

* Tue Jan 31 2023 kircher <majun65@huawei.com> - 1.0.1-48
- add gazelle fuzz
- add log message when wait for connecting to ltran

* Mon Jan 16 2023 kircher <majun65@huawei.com> - 1.0.1-47
- add ret check in pthread_create and fix example bug
- move control_client_thread creation after control_in and dpdk_skip_nic_init

* Fri Jan 6 2023 kircher <majun65@huawei.com> - 1.0.1-46
- add the suggestion of using the -u parameter when the connection to unix socket fails

* Fri Dec 30 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-45
- revert expand recv data buff

* Wed Dec 28 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-44
- pbuf cacheline align
  support main thread affinity
  reduce epoll wakeup

* Fri Dec 23 2022 kircher <majun65@huawei.com> - 1.0.1-43
- fix null pointer deref in stack_broadcast_close
- fix lstack Makefile warning

* Thu Dec 22 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-42
- add dfx rcv_nxt info
  mbuf private cache line align
  send pkts index bug fix
  free recv pkts in main loop

* Wed Dec 21 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-41
- add dfx mempool info
  write without epoll/poll

* Tue Dec 20 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-40
- optimite recv data buff and send pkts index

* Sun Dec 18 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-39
- send pkts bluk to nic
  rpc dont send

* Sat Dec 17 2022 jiangheng <jiangheng14@huawei.com> - 1.0.1-38
- remove mbuf reserve in mbuf alloc

* Sat Dec 17 2022 jiangheng <jiangheng14@huawei.com> - 1.0.1-38
- optimite net type
  app bind numa when epoll/poll create
  stack thread params set dafault value

* Sat Dec 17 2022 kircher <majun65@huawei.com> - 1.0.1-37
- add RXTX_NB_MBUF_MAX to limit mbuf_pool_size to its range

* Fri Dec 16 2022 kircher <majun65@huawei.com> - 1.0.1-36
- move select_thread_path after posix_api_init

* Thu Dec 15 2022 jiangheng <jiangheng14@huawei.com> - 1.0.1-35
- ltran rxtx mbuf pool config by conf

* Thu Dec 15 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-34
- stack thread params config by lstack.conf

* Wed Dec 14 2022 jiangheng <jiangheng14@huawei.com> - 1.0.1-33
- fix kernel event thread bind numa failed

* Tue Dec 13 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-32
- dfx add pcb windows snd buf info
  rxtx mbuf pool config by conf

* Mon Dec 12 2022 kircher <majun65@huawei.com> - 1.0.1-31
- add pdump support in ltran

* Sat Dec 3 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-30
- optimize app thread write buff block

* Fri Dec 2 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-29
- fix epoll_wait report 0 events

* Thu Dec 1 UTC compile_success <980965867@qq.com> - 1.0.1-28
- add malloc init zero
- modify EPOLLOUT event is overwritten

* Mon Nov 28 UTC compile_success <980965867@qq.com> - 1.0.1-27
- fix write event error

* Wed Nov 16 2022 kircher <majun65@huawei.com> - 1.0.1-26
- modify duplicate code
- fix data flow error when use NIC in kernel
- fix lwip send return 0 add err event
- fix pcb snd_buf flip
- avoid send stop when mbuf pool empty
- merge lstack rx tx mbuf pool

* Tue Nov 15 2022 kircher <majun65@huawei.com> - 1.0.1-25
- fix pdump and mutil NIC init fail

* Mon Nov 14 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-24
- support muti nic and fix bugs

* Tue Nov 8 2022 kircher <majun65@huawei.com> - 1.0.1-23
- add pdump support in lstack

* Sat Nov 07 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-22
- resolve the conflict between the eth_dev_ops variable and the dpdk-19.11

* Sat Nov 05 2022 kircher <majun65@huawei.com> - 1.0.1-21
- add kni local support in lstack

* Wed Nov 02 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-20
- add gro
  optimize variable access

* Sat Oct 08 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-19
- refactor event
  addapt for ceph client

* Mon Sep 05 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-18
- backport bugfix and doc

* Mon Aug 08 2022 fushanqing <fushanqing@kylinos.cn> - 1.0.1-17
- Unified license name specification

* Tue Aug 2 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-16
- ltran support muti proc with same ip
- same bugfix and clean code
- modify huge dir dir name

* Thu Jul 26 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-15
- support epoll oneshot

* Thu Jul 21 2022 xiusailong <xiusailong@huawei.com> - 1.0.1-14
- backport upstream patches from repository

* Fri Jul 8 2022 jiangheng <jiangheng14@huawei.com> - 1.0.1-13
- Type:bugfix
- CVE:
- SUG:NA
- DESC:modify eth_dev_ops to lstack_eth_dev_ops
       adapt dpdk19.11

* Thu Jul 7 2022 jiangheng <jiangheng14@huawei.com> - 1.0.1-12
- Type:bugfix
- CVE:
- SUG:NA
- DESC:update readme
       fix some bugs
       refactor pkt read send to improve performance
       refactoe kernle event to improve performanc 

* Thu Jul 7 2022 xiusailong <xiusailong@huawei.com> - 1.0.1-11
- modify the required dpdk version number

* Tue Jun 14 2022 xiusailong <xiusailong@huawei.com> - 1.0.1-10
- adapt to gazelle

* Fri May 27 2022 xiusailong <xiusailong@huawei.com> - 1.0.1-9
- update license lockless queue

* Fri May 20 2022 xiusailong <xiusailong@huawei.com> - 1.0.1-8
- update README.md

* Thu Mar 31 2022 jiangheng <jiangheng12@huawei.com> - 1.0.1-7
- Type:bugfix
- CVE:
- SUG:NA
- DESC:add gazelle.yaml

* Tue Mar 29 2022 jiangheng <jiangheng12@huawei.com> - 1.0.1-6
- refactor event
- add gazellectl lstack constraint

* Fri Mar 18 2022 jiangheng <jiangheng12@huawei.com> - 1.0.1-5
- limit lwip_alloc_pbuf size to TCP_MSS
- sending of sock last data is triggered by lstack iteself 

* Thu Mar 17 2022 jiangheng <jiangheng12@huawei.com> - 1.0.1-4
- fix repeatede stack restart coredump

* Wed Mar 16 2022 jiangheng <jiangheng12@huawei.com> - 1.0.1-3
- fix gazelle test issue

* Mon Mar 7 2022 wu-changsheng <wuchangsheng2@huawei.com> - 1.0.1-2
- reduce copy in send

* Thu Mar 3 2022 wu-changsheng <wuchangsheng2@huawei.com> - 1.0.1-1
- support mysql with two mode:ltran+lstack and lstack.

* Thu Feb 24 2022 wu-changsheng <wuchangsheng2@huawei.com> - 1.0.0-1
- release initial version
