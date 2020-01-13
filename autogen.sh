#!/bin/sh


TARGET=/usr/local/parakeet

tar xvf apr-1.6.3.tar.gz
cd apr-1.6.3 
./configure --prefix=$TARGET
make clean && make && make install

cd ..
tar xvf apr-util-1.6.1.tar.gz
cd apr-util-1.6.1
./configure --prefix=$TARGET --with-apr=$TARGET
make clean && make && make install

cd ..
tar xvf apr-iconv-1.2.2.tar.gz
cd apr-iconv-1.2.2 
./configure --prefix=$TARGET --with-apr=$TARGET
make clean && make && make install

cd ..
tar xvf zlog-1.2.12.tar.gz
cd zlog-1.2.12
make PREFIX=$TARGET
make PREFIX=$TARGET install


#$MAKE maintainer-clean >/dev/null 2>/dev/null
#
#if [ -x "`which autoreconf 2>/dev/null`" ] ; then
#   exec autoreconf -ivf
#fi
#
#LIBTOOLIZE=libtoolize
#SYSNAME=`uname`
#if [ "x$SYSNAME" = "xDarwin" ] ; then
#  LIBTOOLIZE=glibtoolize
#fi
#aclocal -I m4 && \
#	autoheader && \
#	$LIBTOOLIZE && \
#	autoconf && \
#	automake --add-missing --force-missing --copy && \
#	configure --prefix=$TARGET && \
#	make && \
#	make clean && \
#	make install


cd ..
autoreconf
./configure --prefix=$TARGET
make clean && make
make install

