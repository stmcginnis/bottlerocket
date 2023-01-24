Name: %{_cross_os}openssl
Version: 3.0.5
Release: 1%{?dist}
Summary: Library for cryptography
URL: https://www.openssl.org/
License: Apache-2.0
Source: https://www.openssl.org/source/openssl-%{version}.tar.gz
BuildRequires: %{_cross_os}glibc-devel

%description
%{summary}.

%package devel
Summary: Files for development using the library for cryptography
Requires: %{name}

%description devel
%{summary}.

%prep
%setup -n openssl-%{version}

%global set_env \
%set_cross_build_flags \\\
export CC="gcc" \\\
export CXX="g++" \\\
export CROSS_COMPILE="%{_cross_target}-" \\\
%{nil}

%build
NO_FEATURES=""

for algorithm in \
  aria bf blake2 camellia cast des dsa idea md4 \
  mdc2 ocb rc2 rc4 rmd160 scrypt seed siphash siv \
  sm2 sm3 sm4 whirlpool ;
do
  NO_FEATURES+="no-${algorithm} " ; \
done

for feature in \
  cmp cms comp dgram ec2m gost \
  dynamic-engine legacy nextprotoneg padlockeng \
  srp srtp ssl ssl-trace tests ts ui-console \
  dtls dtls1{,-method} dtls1_2{,-method} \
  tls1{,-method} tls1_1{,-method} \
  ;
do
  NO_FEATURES+="no-${feature} " ;
done

%set_env
./Configure \
  --openssldir='%{_cross_sysconfdir}/pki/tls' \
  --prefix='%{_cross_prefix}' \
  --libdir='%{_cross_libdir}' \
  --cross-compile-prefix='%{_cross_target}-' \
  '-DDEVRANDOM="\"/dev/urandom\""' \
  --api=1.1.0 \
  ${NO_FEATURES} \
  enable-ec_nistp_64_gcc_128 \
  "linux-${ARCH}"

perl configdata.pm --dump

%make_build

%install
make DESTDIR=%{buildroot} install_sw

%files
%license LICENSE.txt
%{_cross_attribution_file}
%{_cross_libdir}/*.so.*
%exclude %{_cross_bindir}/openssl
%exclude %{_cross_bindir}/c_rehash

%files devel
%{_cross_libdir}/*.so
%dir %{_cross_includedir}/openssl
%{_cross_includedir}/openssl/*.h
%{_cross_libdir}/*.a
%{_cross_pkgconfigdir}/*.pc
