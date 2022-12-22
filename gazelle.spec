%define conf_path %{_sysconfdir}/%{name}

Name:          gazelle
Version:       1.0.1
Release:       40
Summary:       gazelle is a high performance user-mode stack
License:       MulanPSL-2.0
URL:           https://gitee.com/openeuler/gazelle
Source0:       %{name}-%{version}.tar.gz

BuildRequires: cmake gcc-c++ lwip
BuildRequires: dpdk-devel >= 21.11-5
BuildRequires: numactl-devel libpcap-devel libconfig-devel libboundscheck

Requires:      dpdk >= 21.11-5
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
Patch9040:     0040-fix-sock-invalid-address.patch
Patch9041:     0041-exit-lstack-process-after-ltran-instance-logout.patch
Patch9042:     0042-use-atomic-variales-to-count.patch
Patch9043:     0043-re-arrange-the-program-to-invoke-rte_eth_dev_start-b.patch
Patch9044:     0044-delete-redundant-file.patch
Patch9045:     0045-lstack-all-exit-move-to-init.patch
Patch9046:     0046-clean-code-fix-huge-func.patch
Patch9047:     0047-add-kernel-path-in-epoll-funcs.patch
Patch9048:     0048-refactor-kernel-event-poll-epoll.patch
Patch9049:     0049-post-thread_phase1-sem-to-avoid-block-main-thread-wh.patch
Patch9050:     0050-adjust-the-number-of-RX-TX-mbufs-of-each-stack-threa.patch
Patch9051:     0051-modify-README.patch
Patch9052:     0052-bugfix-https-gitee.com-src-openeuler-gazelle-issues-.patch
Patch9053:     0053-update-README.md.patch
Patch9054:     0054-ltran-fix-use-after-free-issue.patch
Patch9055:     0055-refactor-pkt-read-send-performance.patch
Patch9056:     0056-ltran-support-checksum.patch
Patch9057:     0057-add-examples-readme-compile-components-main-file-and.patch
Patch9058:     0058-add-examples-parameter-parsing.patch
Patch9059:     0059-lstack-core-fix-reta_conf-array-size-calculation.patch
Patch9060:     0060-Replace-gettid-with-rte_gettid.patch
Patch9061:     0061-modify-the-code-for-canonical-and-update-the-cmake-b.patch
Patch9062:     0062-enable-secure-compile-and-open-compile-log.patch
Patch9063:     0063-support-epoll-et-trig-mode.patch
Patch9064:     0064-lstack-support-low-power.patch
Patch9065:     0065-add-port-mask-range-check.patch
Patch9066:     0066-release-kni-device.patch
Patch9067:     0067-optimize-check-ltran-exist.patch
Patch9068:     0068-clean-code.patch
Patch9069:     0069-clean-code.patch
Patch9070:     0070-Support-build-gazelle-with-clang.patch
Patch9071:     0071-Allow-dynamic-load-PMDs.patch
Patch9072:     0072-support-epoll-oneshot.patch
Patch9073:     0073-modify-readme-and-clean-code.patch
Patch9074:     0074-ltran-support-muti-proc-with-same-ip.patch
Patch9075:     0075-fix-rpc-msg-out-of-bound.patch
Patch9076:     0076-fix-traversal-array-use-NULL-pointer.patch
Patch9077:     0077-same-stack-thread-don-t-repeate-send-msg.patch
Patch9078:     0078-fix-memcpy-out-bounds.patch
Patch9079:     0079-fix-miss-send-rpc-msg-err.patch
Patch9080:     0080-fix-proc-can-not-exit-due-to-lack-of-mem-startup-fai.patch
Patch9081:     0081-read-data-with-err-event.patch
Patch9082:     0082-del-gazelle-ring-cons.tail-atomic-protect.patch
Patch9083:     0083-fix-send-return-vale.patch
Patch9084:     0084-add-examples.patch
Patch9085:     0085-expand-thread-rpc-msg-pool-size.patch
Patch9086:     0086-fix-fd-leak.patch
Patch9087:     0087-fix-del-conn-use-after-free.patch
Patch9088:     0088-init-g_gazelle_errno-before-use.patch
Patch9089:     0089-code-format-specification.patch
Patch9090:     0090-fix-gazelle-kernel-event-thread-affinity-same-with-s.patch
Patch9091:     0091-have_corelist_arg.patch
Patch9092:     0092-ltran-update-list.patch
Patch9093:     0093-remove-get_reg_ring_free_count.patch
Patch9094:     0094-add-errorno-EISCONN.patch
Patch9095:     0095-fix-sendmsg-data-write-wrong.patch
Patch9096:     0096-lstack-restore-pci-bus-after-init.patch
Patch9097:     0097-fix-malloc-rpc-msg-fail.patch
Patch9098:     0098-support-dpdk-dynamic-memory.patch
Patch9099:     0099-fix-lwip_send-fail-free-pbuf-miss-data.patch
Patch9100:     0100-merger-wakeup.patch
Patch9101:     0101-conenct-support-multi-queues.patch
Patch9102:     0102-merge-sendmsg-write.patch
Patch9103:     0103-add-thread-select-path.patch
Patch9104:     0104-support-conf-control-app-bind-numa.patch
Patch9105:     0105-fix-epoll_wait-cover-kernel-event.patch
Patch9106:     0106-fix-read-stack-data-return-0-when-no-data.patch
Patch9107:     0107-fix-stack-wakeup-node-del.patch
Patch9108:     0108-avoid-useless-stack-check-wakeup-event.patch
Patch9109:     0109-fix-mesg-loss.patch
Patch9110:     0110-add-accept4-and-epoll_create1.patch
Patch9111:     0111-refactor-event-notice.patch
Patch9112:     0112-add-writev-and-readv.patch
Patch9113:     0113-optimized-some-function-in-lstack.patch
Patch9114:     0114-fix-gazellectl-stats-err-when-donot-bind-numa.patch
Patch9115:     0115-add-usleep-when-write_ring-is-busy.patch
Patch9116:     0116-optimize-variable-access.patch
Patch9117:     0117-add-gro.patch
Patch9118:     0118-expand-nic-rx-desc-size.patch
Patch9119:     0119-add-kni-local-support-in-lstack.patch
Patch9120:     0120-resolve-the-conflict-between-the-eth_dev_ops-variabl.patch
Patch9121:     0121-add-pdump-support-in-lstack.patch
Patch9122:     0122-fix-uninit-stack-port_id-when-use-mutil-NIC.patch
Patch9123:     0123-fix-memleak-in-dpdk_ethdev_init-unlikely-path.patch
Patch9124:     0124-fix-epoll_wait-return-when-timeout-is-0.patch
Patch9125:     0125-fix-gazelle-pdump-init-fail-with-dpdk-21.11.patch
Patch9126:     0126-fix-add-outdated-event.patch
Patch9127:     0127-revert-write-usleep.patch
Patch9128:     0128-reduce-thread-variable-access.patch
Patch9129:     0129-add-readv-and-readv-kernel.patch
Patch9130:     0130-add-unlock-before-after.patch
Patch9131:     0131-add-mutil-NIC-support-in-gazelle.patch
Patch9132:     0132-remove-filename_check-in-gazellectl-to-fix-build-err.patch
Patch9133:     0133-cancel-kernel-sock-epoll-ctl-when-lwip-sock-connect.patch
Patch9134:     0134-modify-readv-and-writev-first-buf-is-null.patch
Patch9135:     0135-fix-pdump-and-mutil-NIC-init-fail.patch
Patch9136:     0136-modify-duplicate-code.patch
Patch9137:     0137-merge-lstack-rx-tx-mbuf-pool.patch
Patch9138:     0138-avoid-send-stop-when-mbuf-pool-empty.patch
Patch9139:     0139-fix-pcb-snd_buf-flip.patch
Patch9140:     0140-fix-lwip-send-return-0-add-err-event.patch
Patch9141:     0141-fix-data-flow-error-when-use-NIC-in-kernel.patch
Patch9142:     0142-fix-write-event-error.patch
Patch9143:     0143-add-malloc-init-zero.patch
Patch9144:     0144-modify-event-error.patch
Patch9145:     0145-add-unix_prefix-in-gazellectl.patch
Patch9146:     0146-fix-epoll_wait-report-event0.patch
Patch9147:     0147-add-TSO.patch
Patch9148:     0148-optimize-app-thread-write-buff-block.patch
Patch9149:     0149-expand-rxtx-mbuf-pool.patch
Patch9150:     0150-add-pdump-support-in-ltran.patch
Patch9151:     0151-dfx-gazellectl-add-pcb-wins-info.patch
Patch9152:     0152-fix-genarate-out-event-untimely.patch
Patch9153:     0153-rxtx-mbuf-pool-size-config-by-conf.patch
Patch9154:     0154-fix-kernel-event-thread-bind-numa-failed.patch
Patch9155:     0155-stack-thread-parms-config-by-conf.patch
Patch9156:     0156-ltran-rxtx-mbuf-pool-size-config-by-conf.patch
Patch9157:     0157-move-select_thread_path-after-posix_api_init.patch
Patch9158:     0158-add-RXTX_NB_MBUF_MAX-to-limit-mbuf_pool_size-to-its-.patch
Patch9159:     0159-stack-thread-params-default-val.patch
Patch9160:     0160-optimite-net-type.patch
Patch9161:     0161-app-bind-numa-when-epoll-poll-create.patch
Patch9162:     0162-remove-mbuf-reserve-in-mbuf-alloc.patch
Patch9163:     0163-pkts-bulk-send-to-nic.patch
Patch9164:     0164-rpc-dont-send.patch
Patch9165:     0165-recv-pbuf-free-timely.patch
Patch9166:     0166-optimite-send-pkts-dul-index.patch
Patch9167:     0167-expand-data-recv-buff.patch
Patch9168:     0168-dfx-add-mempool-count-info.patch
Patch9169:     0169--write-support-without-epoll-poll.patch
Patch9170:     0170-add-rcv-nxt-dfx-info.patch
Patch9171:     0171-mbuf-private-data-size-align-cache-line.patch
Patch9172:     0172-fix-send-pkts-bluk-err.patch
Patch9173:     0173-free-recv-pkts-bluks.patch

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
* Thu Dec 22 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-40
- add dfx rcv_nxt info
  mbuf private cache line align
  send pkts index bug fix
  free recv pkts in main loop

* Wed Dec 21 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-39
- add mempool dfx info
  write support without epoll/poll

* Tue Dec 20 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-38
- optimite recv data buff and send pkts index

* Sun Dec 18 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-37
- pkts-bulk-send-to-nic and rpc-dont-send

* Sat Dec 17 2022 jiangheng <jiangheng14@huawei.com> - 1.0.1-36
- remove mbuf reserve in mbuf alloc

* Sat Dec 17 2022 jiangheng <jiangheng14@huawei.com> - 1.0.1-35
- optimite net type
  app bind numa when epoll/poll create
  stack thread params set dafult value

* Sat Dec 17 2022 kircher <majun65@huawei.com> - 1.0.1-34
- add RXTX_NB_MBUF_MAX to limit mbuf_pool_size to its range

* Fri Dec 16 2022 kircher <majun65@huawei.com> - 1.0.1-33
- move select_thread_path after posix_api_init

* Thu Dec 15 2022 jiangheng <jiangheng14@huawei.com> - 1.0.1-32
- ltran rxtx mbuf pool size config by conf

* Thu Dec 15 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-31
- stack thread params config by lstack.conf

* Wed Dec 14 2022 jiangheng <jiangheng14@huawei.com> - 1.0.1-30
- fix kernel event thread bind nuam failed

* Tue Dec 13 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-29
- dfx add pcb windows info
  rxtx mbuf pool size config by conf

* Mon Dec 12 2022 kircher <majun65@huawei.com> - 1.0.1-28
- add pdump support in ltran

* Sat Dec 3 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-27
- optimize app thread write buff block

* Fri Dec 2 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-26
- fix epoll_wait report events 0

* Thu Dec 1 UTC compile_success <980965867@qq.com> - 1.0.1-25
- add malloc init zero
- modify EPOLLOUT event is overwritten.

* Sat Nov 26 UTC compile_success <980965867@qq.com> - 1.0.1-24
- fix write event error

* Wed Nov 16 2022 kircher <majun65@huawei.com> - 1.0.1-23
- modify duplicate code
- fix data flow error when use NIC in kernel
- fix lwip send return 0 add err event
- fix pcb snd_buf flip
- avoid send stop when mbuf pool empty
- merge lstack rx tx mbuf pool

* Tue Nov 15 2022 kircher <majun65@huawei.com> - 1.0.1-22
- fix pdump and mutil NIC init fail

* Mon Nov 14 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-21
- support muti-nic
  fix some bugs

* Tue Nov 8 2022 kircher <majun65@huawei.com> - 1.0.1-20
- add pdump support in lstack

* Sat Nov 07 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-19
- resolve the conflict between the eth_dev_ops variable and the dpdk-19.11

* Sat Nov 05 2022 kircher <majun65@huawei.com> - 1.0.1-18
- Add kni local support in lstack

* Fri Nov 04 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-17
- Optimize ceph client performance

* Sat Oct 08 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-16
- refactor event
  addapt for ceph client

* Mon Sep 05 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-15
- expand rpc msg pool size

* Mon Sep 05 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-14
- backport bugfix and doc

* Mon Aug 08 2022 fushanqing <fushanqing@kylinos.cn> - 1.0.1-13
- Unified license name specification

* Tue Jul 26 2022 wuchangsheng <wuchangsheng2@huawei.com> - 1.0.1-12
- support epoll oneshot 

* Tue Jul 19 2022 xiusailong <xiusailong@huawei.com> - 1.0.1-11
- reconstruct packet sending and receiving to improve performance 

* Thu Jul 7 2022 jiangheng <jiangheng14@huawei.com> - 1.0.1-10
- Type:bugfix
- CVE:
- SUG:NA
- DESC:update readme
       fix some bugs
       refactor pkt read send to improve performance
       refactoe kernle event to improve performanc 

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
