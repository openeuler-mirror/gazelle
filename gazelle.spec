%define conf_path %{_sysconfdir}/%{name}

Name:          gazelle
Version:       1.0.0
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

%description
%{name} is a high performance user-mode stack.

ExclusiveArch: x86_64 aarch64

%prep
%autosetup -n %{name}-v%{version}

%build
cd %{_builddir}/%{name}-v%{version}
# Add compile option, ignore map address check. Scenarios: asan test
%if 0%{?gazelle_map_addr_nocheck}
    sed -i 's/-pthread/-pthread -D gazelle_map_addr_nocheck/' %{_builddir}/%{name}-v%{version}/src/ltran/CMakeLists.txt
%endif
sh build/build.sh

%install
install -dpm 0755 %{buildroot}/%{_bindir}
install -dpm 0755 %{buildroot}/%{_prefix}/lib64
install -dpm 0750 %{buildroot}/%{conf_path}

install -Dpm 0500 %{_builddir}/%{name}-v%{version}/src/lstack/liblstack.*     %{buildroot}/%{_libdir}/
install -Dpm 0640 %{_builddir}/%{name}-v%{version}/src/lstack/lstack.Makefile %{buildroot}/%{conf_path}/
install -Dpm 0640 %{_builddir}/%{name}-v%{version}/src/lstack/lstack.conf     %{buildroot}/%{conf_path}/

install -Dpm 0500 %{_builddir}/%{name}-v%{version}/src/ltran/gazellectl       %{buildroot}/%{_bindir}/
install -Dpm 0500 %{_builddir}/%{name}-v%{version}/src/ltran/ltran            %{buildroot}/%{_bindir}/
install -Dpm 0640 %{_builddir}/%{name}-v%{version}/src/ltran/ltran.conf       %{buildroot}/%{conf_path}/

%files
%defattr(-,root,root)
%dir %{conf_path}
%{_bindir}/*
%{_libdir}/liblstack.*
%{conf_path}/lstack.Makefile
%config(noreplace) %{conf_path}/lstack.conf
%config(noreplace) %{conf_path}/ltran.conf

%changelog
* Thu Feb 24 2022 - 1.0.0-1
- Type:requirement
- CVE:NA
- SUG:NA
- DESC:release initial version
