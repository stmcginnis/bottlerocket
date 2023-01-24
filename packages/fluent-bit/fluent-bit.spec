# Fluent-bit log collector package

# Disable generate of debuginfo package
# %%global debug_package %%{nil}

# Set debugging information entries (DIEs)
# %%global _dwz_low_mem_die_limit 0

Name: %{_cross_os}fluent-bit
Version: 2.0.8
Release: 1%{?dist}
Summary: Fast and Lightweight Logs and Metrics processor
License: Apache-2.0

URL: https://github.com/fluent/fluent-bit
Source0: https://github.com/fluent/fluent-bit/archive/v${version}/fluent-bit-v%{version}.tar.gz

BuildRequires: git
BuildRequires: cmake
BuildRequires: bison
BuildRequires: flex
BuildRequires: %{_cross_os}glibc-devel
BuildRequires: %{_cross_os}openssl-devel

%description
%{summary}.

%prep
%autosetup -Sgit -c -n fluent-bit-%{version}
#%%autosetup -n fluent-bit-%{version} # -p1
#%%setup -c -q

%build
cd fluent-bit-%{version}/build
#cd build
%set_cross_build_flags \
  %{cross_cmake} \
  -DGNU_HOST="%{_cross_target}" \
  -DFLB_CONFIG_YAML=Off \
  -DFLB_LUAJIT=Off \
  -DFLB_SHARED_LIB=Off \
  -DFLB_DEBUG=No \
  -DFLB_RELEASE=Yes \
  -DFLB_EXAMPLES=Off \
    -DCMAKE_C_SYSTEM_NAME:STRING="Linux" \
    -DCMAKE_C_COMPILER:STRING="%{_cross_target}-gcc" \
    -DCMAKE_C_FLAGS_RELEASE:STRING="-DNDEBUG" \
    -DCMAKE_CXX_FLAGS_RELEASE:STRING="-DNDEBUG" \
    -DCMAKE_BUILD_TYPE="Release" \
    -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
    -DCMAKE_INSTALL_PREFIX:PATH=%{_cross_prefix} \
    -DINCLUDE_INSTALL_DIR:PATH=%{_cross_includedir} \
    -DLIB_INSTALL_DIR:PATH=%{_cross_libdir} \
    -DSYSCONF_INSTALL_DIR:PATH=%{_cross_sysconfdir} \
    -DSHARE_INSTALL_PREFIX:PATH=%{_cross_datadir} \
    -DBUILD_SHARED_LIBS:BOOL=ON \
    -DCMAKE_SKIP_RPATH:BOOL=ON \
    ..
#   %{shrink:%{__cmake} \
#     -DCMAKE_C_SYSTEM_NAME:STRING="Linux" \
#     -DCMAKE_C_COMPILER:STRING="%{_cross_target}-gcc" \
#     -DCMAKE_C_FLAGS_RELEASE:STRING="-DNDEBUG" \
#     -DCMAKE_CXX_FLAGS_RELEASE:STRING="-DNDEBUG" \
#     -DCMAKE_BUILD_TYPE="Release" \
#     -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
#     -DCMAKE_INSTALL_PREFIX:PATH=%{_cross_prefix} \
#     -DINCLUDE_INSTALL_DIR:PATH=%{_cross_includedir} \
#     -DLIB_INSTALL_DIR:PATH=%{_cross_libdir} \
#     -DSYSCONF_INSTALL_DIR:PATH=%{_cross_sysconfdir} \
#     -DSHARE_INSTALL_PREFIX:PATH=%{_cross_datadir} \
#     -DBUILD_SHARED_LIBS:BOOL=ON \
#     -DCMAKE_SKIP_RPATH:BOOL=ON \
#     -DFLB_CONFIG_YAML=Off \
#     %{nil}}  ..
%make_build
cd sdfsdfg

%install
cd %{gorepo}-%{gover}/build
%make_install

%cross_generate_attribution

%files
%license LICENSE
%{_cross_attribution_file}

%changelog
