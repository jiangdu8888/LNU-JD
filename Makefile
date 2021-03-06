
prefix = /usr/local
datadir = ${datarootdir}
datarootdir = ${prefix}/share
SHELL=/bin/sh
OS := $(shell uname -s)
PWD=/home/jiang/ntopng-3.6.1
GPP=g++
INSTALL_DIR=$(DESTDIR)$(prefix)
MAN_DIR=$(DESTDIR)/usr/local/man

# FreeBSD does not include wget by default, but the base system
# includes fetch, which provides similar functionality.
ifeq ($(OS), $(filter $(OS), FreeBSD))
	GET_UTIL = fetch
else
	GET_UTIL = wget -nc
endif

######
NDPI_LIB = ./nDPI/src/lib/libndpi.a
NDPI_INC = -I./nDPI/src/include -I./nDPI/src/lib/third_party/include
NDPI_LIB_DEP = ./nDPI/src/lib/libndpi.a
######
LIBPCAP=-lpcap
######
MONGOOSE_HOME=${PWD}/third-party/mongoose
MONGOOSE_INC=-I$(MONGOOSE_HOME)
######

# Set USE_LUAJIT=0 to use the standard Lua (no JIT)
USE_LUAJIT=1

ifeq ($(OS),Darwin)
USE_LUAJIT=0
endif

ifeq ($(USE_LUAJIT), 0)
  LUAJIT_INC = $(shell pkg-config --cflags lua) -DDONT_USE_LUAJIT
  LUAJIT_LIB = $(shell pkg-config --libs lua)
  HAS_LUAJIT=0
else
  # LUAJIT_HOME=${PWD}/third-party/LuaJIT-2.1.0-beta3
  LUAJIT_HOME=${PWD}/third-party/LuaJIT-2.1.0-git
  LUAJIT_INC=-I$(LUAJIT_HOME)/src
  LUAJIT_LIB=$(LUAJIT_HOME)/src/libluajit.a
endif

######
LIBRRDTOOL_HOME=${PWD}/third-party/rrdtool-1.4.8
HAS_LIBRRDTOOL=$(shell pkg-config --atleast-version=1.4.8 librrd; echo $$?)
ifeq ($(HAS_LIBRRDTOOL), 0)
	LIBRRDTOOL_INC = $(shell pkg-config --cflags librrd)
	LIBRRDTOOL_LIB = $(shell pkg-config --libs librrd) # -lrrd_th
else
	LIBRRDTOOL_INC=-I$(LIBRRDTOOL_HOME)/src/
	ifeq ($(OS), $(filter $(OS), OpenBSD FreeBSD))
		LIBRRDTOOL_LIB=$(LIBRRDTOOL_HOME)/src/.libs/librrd_th.a -lm -lgobject-2.0 -lgmodule-2.0 -lglib-2.0	
	else
		LIBRRDTOOL_LIB=$(LIBRRDTOOL_HOME)/src/.libs/librrd_th.a -lm -lgobject-2.0 -lgmodule-2.0 -ldl -lglib-2.0
	endif
endif
######
ifeq ($(OS), $(filter $(OS), FreeBSD))
	ifneq (, $(wildcard "${PWD}/../PF_RING/userland/nbpf/libnbpf.a"))
		LIBNBPF_HOME=${PWD}/../PF_RING/userland/nbpf
		LIBNBPF_LIB=$(LIBNBPF_HOME)/libnbpf.a
	endif
endif

######

HTTPCLIENT_INC=${PWD}/third-party/http-client-c/src/

######

HAS_JSON=$(shell pkg-config --exists json-c; echo $$?)
ifeq ($(HAS_JSON), 0)
	JSON_INC = $(shell pkg-config --cflags json-c)
	JSON_LIB = $(shell pkg-config --libs json-c)
else
	JSON_HOME=${PWD}/third-party/json-c
	JSON_INC=-I$(JSON_HOME)
	JSON_LIB=$(JSON_HOME)/.libs/libjson-c.a
endif

######

ifeq (0, 0)
 HAS_SODIUM=$(shell pkg-config --exists libsodium; echo $$?)
 ifeq ($(HAS_SODIUM), 0)
	SODIUM_INC = $(shell pkg-config --cflags libsodium)
	SODIUM_LIB = $(shell pkg-config --libs libsodium)
 else
	SODIUM_INC=
	SODIUM_LIB=
 endif

 HAS_ZEROMQ=$(shell pkg-config --exists libzmq; echo $$?)
 ifeq ($(HAS_ZEROMQ), 0)
	ZEROMQ_INC = $(shell pkg-config --cflags libzmq)
	ZMQ_STATIC=/usr/local/lib/libzmq.a
	ifeq ($(wildcard $(ZMQ_STATIC)),)
		ZEROMQ_LIB = $(shell pkg-config --libs libzmq)
	else
		ZEROMQ_LIB = $(ZMQ_STATIC)
	endif
 else
	ZEROMQ_HOME=${PWD}/third-party/zeromq-4.1.3
	ZEROMQ_INC=-I$(ZEROMQ_HOME)/include
	ZEROMQ_LIB=$(ZEROMQ_HOME)/.libs/libzmq.a
 endif

 HAS_ZSTD=$(shell pkg-config --exists libzstd; echo $$?)
 ifeq ($(HAS_ZSTD), 0)
	ZSTD_LIB = $(shell pkg-config --libs libzstd)
 endif
endif

######
TARGET = ntopng
NLIBS = $(NDPI_LIB) $(LIBPCAP) $(LUAJIT_LIB) $(LIBRRDTOOL_LIB) $(LIBNBPF_LIB) $(ZEROMQ_LIB) $(JSON_LIB) -lmaxminddb $(SODIUM_LIB) -lhiredis -lhiredis -lsqlite3 -L/usr/lib/x86_64-linux-gnu -lmysqlclient -lpthread -lz -lm -lrt -ldl -lssl -lssl -lcrypto   -L/usr/local/lib -lcap -lrt -lz -ldl -lcurl  $(ZSTD_LIB) -lm -lpthread
CPPFLAGS = -g -Wall -I/home/jiang/ntopng-3.6.1 -I/home/jiang/ntopng-3.6.1/include -I/usr/local/include -D_FILE_OFFSET_BITS=64 -I/usr/include/hiredis -I/usr/include/hiredis $(MONGOOSE_INC) $(JSON_INC) $(SODIUM_INC) $(NDPI_INC) $(LUAJIT_INC) $(LIBRRDTOOL_INC) $(ZEROMQ_INC) -I/usr/include/mysql  -I/home/jiang/ntopng-3.6.1 -I/home/jiang/ntopng-3.6.1/include -I/usr/local/include -I$(HTTPCLIENT_INC)  -I/usr/include/openssl  -DDATA_DIR='"$(datadir)"' -I${PWD}/third-party/libgeohash -I${PWD}/third-party/patricia # -D_GLIBCXX_DEBUG
######
# ntopng-1.0_1234.x86_64.rpm
PLATFORM = `uname -p`
REVISION = 1.0.181001
PACKAGE_VERSION = 1.0.181001
NTOPNG_VERSION = 1.0.181001
RPM_PKG = $(TARGET)-$(NTOPNG_VERSION)-2.$(PLATFORM).rpm
RPM_PCAP_PKG = $(TARGET)-pcap-$(NTOPNG_VERSION)-2.$(PLATFORM).rpm
RPM_DATA_PKG = $(TARGET)-data-$(NTOPNG_VERSION)-2.noarch.rpm
######

LIB_TARGETS =

ifneq ($(HAS_LUAJIT), 0)
LIB_TARGETS += $(LUAJIT_LIB)
endif

ifneq ($(HAS_ZEROMQ), 0)
LIB_TARGETS += $(ZEROMQ_LIB)
endif

ifneq ($(HAS_LIBRRDTOOL), 0)
LIB_TARGETS += $(LIBRRDTOOL_LIB)
endif

ifneq ($(HAS_JSON), 0)
LIB_TARGETS += $(JSON_LIB)
endif

.PHONY: default all clean docs test

.NOTPARALLEL: default all

default: $(NDPI_LIB_DEP) $(LIB_TARGETS) $(TARGET)

all: default

OBJECTS = $(patsubst src/%.cpp, src/%.o, $(wildcard src/*.cpp)) 
HEADERS = $(wildcard include/*.h) 

%.o: %.c $(HEADERS) Makefile
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

%.o: %.cpp $(HEADERS) Makefile
	$(GPP) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS) $(LIBRRDTOOL) Makefile
	$(GPP) $(OBJECTS) -Wall $(NLIBS) -o $@

$(LUAJIT_LIB):
	cd $(LUAJIT_HOME); make

$(ZEROMQ_LIB):
	cd $(ZEROMQ_HOME); ./configure --without-documentation --without-libsodium; make

# --disable-rrd_graph
$(LIBRRDTOOL_LIB):
	cd $(LIBRRDTOOL_HOME); ./configure --disable-libdbi --disable-libwrap --disable-rrdcgi --disable-libtool-lock --disable-nls --disable-rpath --disable-perl --disable-ruby --disable-lua --disable-tcl --disable-python --disable-dependency-tracking --disable-rrd_graph ; cd src; make librrd_th.la

$(JSON_LIB):
	cd $(JSON_HOME); ./autogen.sh; ./configure; make

clean:
	-rm -f src/*.o src/*~ include/*~ *~ #config.h
	-rm -f $(TARGET)

cert:
	openssl req -new -x509 -sha256 -extensions v3_ca -nodes -days 365 -out cert.pem
	cat privkey.pem cert.pem > httpdocs/ssl/ntopng-cert.pem
	/bin/rm -f privkey.pem cert.pem

veryclean: clean
	-rm -rf nDPI

geoip:
	$(GET_UTIL) http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz
	$(GET_UTIL) http://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN.tar.gz
#	bsdtar does not support --wildcards
	tar xfvz GeoLite2-ASN.tar.gz --strip 1 --wildcards "**/*.mmdb" || tar xfvz GeoLite2-ASN.tar.gz --strip 1 "**/*.mmdb"
	tar xfvz GeoLite2-City.tar.gz --strip 1 --wildcards "**/*.mmdb" || tar xfvz GeoLite2-City.tar.gz --strip 1 "**/*.mmdb"
	mv *.mmdb httpdocs/geoip
	rm -rf GeoLite2*.tar.gz

trackers:
	./tools/download_trackers.sh httpdocs/other/trackers.txt

# Do NOT build package as root (http://wiki.centos.org/HowTos/SetupRpmBuildEnvironment)
#	mkdir -p $(HOME)/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
#	echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros

build-rpm: geoip build-rpm-ntopng build-rpm-ntopng-data


protools:
	cd pro; make

build-rpm-ntopng: ntopng protools
	rpmbuild -bb ./packages/ntopng.spec
	@./packages/rpm-sign.exp $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(RPM_PKG)
	@if test -f $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(RPM_PCAP_PKG) ; then \
	 ./packages/rpm-sign.exp $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(RPM_PCAP_PKG); \
	fi
	@echo ""
	@echo "Package contents:"
	@rpm -qpl $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(RPM_PKG)
	@echo "The package is now available in $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(RPM_PKG)"
	@echo "The package is now available in $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(RPM_PCAP_PKG)"

build-rpm-ntopng-data: geoip
	rpmbuild -bb ./packages/ntopng-data.spec
	@./packages/rpm-sign.exp $(HOME)/rpmbuild/RPMS/noarch/$(RPM_DATA_PKG)
	@echo ""
	@echo "Package contents:"
	@rpm -qpl $(HOME)/rpmbuild/RPMS/noarch/$(RPM_DATA_PKG)
	@echo "The package is now available in $(HOME)/rpmbuild/RPMS/noarch/$(RPM_DATA_PKG)"

docs:
	cd doc && doxygen doxygen.conf

dist:
	rm -rf ntopng-1.0.181001
	mkdir ntopng-1.0.181001
	cd ntopng-1.0.181001; git clone https://github.com/ntop/ntopng.git; cd ntopng; git clone https://github.com/ntop/nDPI.git; cd ..; find ntopng -name .git | xargs rm -rf ; mv ntopng ntopng-1.0.181001; tar cvfz ../ntopng-1.0.181001.tgz ntopng-1.0.181001

install: ntopng
	@echo "Make sure you have already run 'make geoip' to also install geoip dat files"
	@echo "While we provide you an install make target, we encourage you"
	@echo "to create a package and install that"
	@echo "rpm - do 'make build-rpm'"
	@echo "deb - do 'cd packages/ubuntu;./configure;make"
	mkdir -p $(INSTALL_DIR)/share/ntopng $(MAN_DIR)/man8 $(INSTALL_DIR)/bin
	cp ntopng $(INSTALL_DIR)/bin
	cp ./ntopng.8 $(MAN_DIR)/man8
	cp -r ./httpdocs $(INSTALL_DIR)/share/ntopng
	cp -LR ./scripts $(INSTALL_DIR)/share/ntopng # L dereference symlinks
	find $(INSTALL_DIR)/share/ntopng -name "*~"   | xargs /bin/rm -f
	find $(INSTALL_DIR)/share/ntopng -name ".git" | xargs /bin/rm -rf

uninstall:
	if test -f $(INSTALL_DIR)/bin/ntopng; then rm $(INSTALL_DIR)/bin/ntopng; fi;
	if test -f $(MAN_DIR)/man8/ntopng.8; then rm $(MAN_DIR)/man8/ntopng.8; fi;
	if test -d $(INSTALL_DIR)/share/ntopng; then rm -r $(INSTALL_DIR)/share/ntopng; fi;

Makefile: configure Makefile.in
	./configure

minify:
	cd httpdocs/js; make UGLIFY_VERSION= minify

# Disabled to avoid too many recompilations
#configure: .git/index
#	@echo ""
#	@echo "Re-running autogen as the git release has changed"
#	@echo ""
#	./autogen.sh

cppcheck:
	cppcheck --template='{file}:{line}:{severity}:{message}' --quiet --enable=all --force -I include/ -D_FILE_OFFSET_BITS=64 -I/usr/include/hiredis -I/usr/include/hiredis $(MONGOOSE_INC) $(JSON_INC) $(NDPI_INC) $(LUAJIT_INC) $(LIBRRDTOOL_INC) $(ZEROMQ_INC) src/*.cpp

test: test_version

test_version:
	./ntopng --version

webtest:
	echo "Assuming default HTTP port and default credentials"
	cd /tmp
	rm -rf localhost:3000
	wget --auth-no-challenge -mk --user admin --password admin http://localhost:3000

changelog:
	git log --since={`curl -s https://github.com/ntop/ntopng/releases | grep datetime | head -n1 | egrep -o "[0-9]+\-[0-9]+\-[0-9]+"`} --name-only --pretty=format:" - %s" > Changelog.latest
	if [ -d pro ]; then cd pro && git log --since={`curl -s https://github.com/ntop/ntopng/releases | grep datetime | head -n1 | egrep -o "[0-9]+\-[0-9]+\-[0-9]+"`} --name-only --pretty=format:" - %s" >> ../Changelog.latest; fi
