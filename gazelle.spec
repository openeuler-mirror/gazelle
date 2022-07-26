%define conf_path %{_sysconfdir}/%{name}

Name:          gazelle
Version:       1.0.1
Release:       12
Summary:       gazelle is a high performance user-mode stack
License:       Mulan PSL v2
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
