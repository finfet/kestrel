# Need to tell rpmbuild not to expect a debug binary
%global _enable_debug_package 0
%global debug_package %{nil}

%ifarch x86_64
%define bin_arch amd64
%endif
%ifarch aarch64
%define bin_arch arm64
%endif

Name: kestrel
Version: 0.10.1
Release: 1
Summary: File encryption done right

License: BSD-3-Clause
URL: https://getkestrel.com
Source0: %{name}-linux-v%{version}-%{bin_arch}.tar.gz

# libc6 deps are picked up automatically by rpmbuild analyzing the binary

%description
Kestrel is a file encryption utility that lets you encrypt files to
anyone with a public key.

%prep
%autosetup -n %{name}-linux-v%{version}-%{bin_arch}

%build
gzip -k man/kestrel.1

%install
mkdir -p $RPM_BUILD_ROOT/%{_bindir}
install -m 755 kestrel $RPM_BUILD_ROOT/%{_bindir}
mkdir -p $RPM_BUILD_ROOT/%{_mandir}/man1
install -m 644 man/kestrel.1.gz $RPM_BUILD_ROOT/%{_mandir}/man1
mkdir -p $RPM_BUILD_ROOT/%{_docdir}/kestrel
install -m 644 LICENSE.txt $RPM_BUILD_ROOT/%{_docdir}/kestrel
install -m 644 THIRD-PARTY-LICENSE.txt $RPM_BUILD_ROOT/%{_docdir}/kestrel
mkdir -p $RPM_BUILD_ROOT/usr/share/bash-completion/completions
install -m 644 completion/kestrel.bash-completion $RPM_BUILD_ROOT/usr/share/bash-completion/completions/kestrel

%files
# Make sure we know about the kestrel doc folder so we can delete it
%dir %{_docdir}/kestrel
%{_bindir}/%{name}
%{_mandir}/man1/kestrel.1.gz
%{_docdir}/kestrel/LICENSE.txt
%{_docdir}/kestrel/THIRD-PARTY-LICENSE.txt
/usr/share/bash-completion/completions/kestrel

%changelog
* Mon Jul 04 2022 Kyle Schreiber <kyle@80x24.net> - 0.10.0-1
- Warn on use of empty password.
