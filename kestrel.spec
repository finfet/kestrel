# Need to tell rpmbuild not to expect a debug binary
%global _enable_debug_package 0
%global debug_package %{nil}

%ifarch x86_64
%define bin_arch amd64
%endif
%ifarch aarch64
%define bin_arch arm64
%endif

%define alt_ver 1.0.2

Name: kestrel
Version: 1.0.2
Release: 1
Summary: File encryption done right

License: BSD-3-Clause
URL: https://getkestrel.com
Source0: %{name}-linux-v%{alt_ver}-%{bin_arch}.tar.gz

# libc6 deps are picked up automatically by rpmbuild analyzing the binary

%description
Kestrel is a file encryption utility that lets you encrypt files to anyone
with a public key.

%prep
%autosetup -n %{name}-linux-v%{alt_ver}-%{bin_arch}

%build
gzip -k man/kestrel.1

%install
install -D -p -m=755 kestrel %{buildroot}%{_bindir}/kestrel
install -D -p -m=644 man/kestrel.1.gz %{buildroot}%{_mandir}/man1/kestrel.1.gz
install -D -p -m=644 LICENSE.txt %{buildroot}%{_docdir}/kestrel/LICENSE.txt
install -D -p -m=644 THIRD-PARTY-LICENSE.txt %{buildroot}%{_docdir}/kestrel/THIRD-PARTY-LICENSE.txt
install -D -p -m=644 completion/kestrel.bash-completion %{buildroot}/%{bash_completions_dir}/kestrel

%files
# Make sure we know about the kestrel doc folder so we can delete it
%dir %{_docdir}/kestrel
%{_bindir}/%{name}
%{_mandir}/man1/kestrel.1.gz
%{_docdir}/kestrel/LICENSE.txt
%{_docdir}/kestrel/THIRD-PARTY-LICENSE.txt
%{bash_completions_dir}/kestrel

%changelog
* Sun Jul 07 2024 Kyle Schreiber <kyle@80x24.net> - 1.0.2-1
- Fall back to using stdin if a tty cannot be opened.
- Upgrade the underlying curve25519 dependency
