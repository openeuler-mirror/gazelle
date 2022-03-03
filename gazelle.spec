%define conf_path %{_sysconfdir}/%{name}

Name:          gazelle
Version:       1.0.1
Release:       1
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
* Thu Mar 3 2022 wu-changsheng <wuchangsheng@huawei.com> - 1.0.1-1
- support mysql with two mode:ltran+lstack and lstack.

* Thu Feb 24 2022 wu-changsheng <wuchangsheng@huawei.com> - 1.0.0-1
- release initial version
