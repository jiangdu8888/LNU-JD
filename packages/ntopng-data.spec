Summary: GeoIP databases for ntopng
Name: ntopng-data
Version: 3.6.181020
Release: 0
License: GPL
Group: Networking/Utilities
URL: http://www.ntop.org/
Source: ntopng-data-%{version}.tgz
Packager: Luca Deri <deri@ntop.org>
BuildArch: noarch
# Temporary location where the RPM will be built
BuildRoot:  %{_tmppath}/%{name}-%{version}-root
#Requires: ntopng

%description
GeoIP databases for ntopng

%prep

%build

mkdir -p $RPM_BUILD_ROOT/usr/share/ntopng/httpdocs/geoip
# old .dat GeoLite databases are superseded by GeoLite2 .mmdb
# cp $HOME/ntopng/httpdocs/geoip/*.dat  $RPM_BUILD_ROOT/usr/share/ntopng/httpdocs/geoip
cp $HOME/ntopng/httpdocs/geoip/*.mmdb $RPM_BUILD_ROOT/usr/share/ntopng/httpdocs/geoip
find $RPM_BUILD_ROOT -type f -not -name "*.mmdb" | xargs /bin/rm -rf

#
DST=$RPM_BUILD_ROOT/usr/ntopng
SRC=$RPM_BUILD_DIR/%{name}-%{version}
# Clean out our build directory
%clean
rm -fr $RPM_BUILD_ROOT

%files
# /usr/share/ntopng/httpdocs/geoip/GeoIPASNum.dat
# /usr/share/ntopng/httpdocs/geoip/GeoIPASNumv6.dat
# /usr/share/ntopng/httpdocs/geoip/GeoLiteCity.dat
# /usr/share/ntopng/httpdocs/geoip/GeoLiteCityv6.dat
/usr/share/ntopng/httpdocs/geoip/GeoLite2-ASN.mmdb
/usr/share/ntopng/httpdocs/geoip/GeoLite2-City.mmdb

# Set the default attributes of all of the files specified to have an
# owner and group of root and to inherit the permissions of the file
# itself.
%defattr(-, root, root)

%changelog

