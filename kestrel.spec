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
Version: 1.0.0-rc1
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
mkdir -p %{buildroot}/%{_bindir}
install -m 755 kestrel %{buildroot}/%{_bindir}
mkdir -p %{buildroot}/%{_mandir}/man1
install -m 644 man/kestrel.1.gz %{buildroot}/%{_mandir}/man1
mkdir -p %{buildroot}/%{_docdir}/kestrel
install -m 644 LICENSE.txt %{buildroot}/%{_docdir}/kestrel
install -m 644 THIRD-PARTY-LICENSE.txt %{buildroot}/%{_docdir}/kestrel
mkdir -p %{buildroot}/usr/share/bash-completion/completions
install -m 644 completion/kestrel.bash-completion %{buildroot}/usr/share/bash-completion/completions/kestrel

%files
# Make sure we know about the kestrel doc folder so we can delete it
%dir %{_docdir}/kestrel
%{_bindir}/%{name}
%{_mandir}/man1/kestrel.1.gz
%{_docdir}/kestrel/LICENSE.txt
%{_docdir}/kestrel/THIRD-PARTY-LICENSE.txt
/usr/share/bash-completion/completions/kestrel

%changelog
* Fri Jan 20 2023 Kyle Schreiber <kyle@80x24.net> - 0.10.1-1
- Fixed crash when running kestrel key
- Improved cli error message output
* Mon Jul 04 2022 Kyle Schreiber <kyle@80x24.net> - 0.10.0-1
- Warn on use of empty password.
