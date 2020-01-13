# network packet sniffer and decode audio server 

AM_CFLAGS = -g -O3 -Wall -I$(prefix)/include -D_DEBUG
AM_CPPFLAGS = -I$(prefix)/include

bin_PROGRAMS = parakeet

#####################################################################
# Source files
parakeet_SOURCES = \
            parakeet_main.c \
            parakeet_stream.c \
            parakeet_config.c \
			parakeet_codec.c \
            parakeet_core_mysqldb.c \
            parakeet_core_sniffer.c \
            parakeet_event_socket.c \
            parakeet_session.c 

#####################################################################
#load flags
parakeet_LDFLAGS = $(AM_LDFLAGS) -lpthread -Wl,-rpath $(prefix)/lib

#####################################################################
# Library files
parakeet_LDADD = \
              -L$(prefix)/lib \
              -lapr-1 \
              -laprutil-1 \
              -lzlog \
              -lpcap \
              -lfranksip

#####################################################################
# Configuration files
confdir = $(prefix)/conf
conf_DATA = \
         ../conf/log.conf \
         ../conf/parakeet.xml 
        
#####################################################################
# Script files 
exedir = $(prefix)/bin
exe_DATA = \
         ../scripts/parakeet.sh \
         ../scripts/pk_guard.sh


httpdir = ../http/*

# Package Files
EXTRA_DIST = $(conf_DATA) $(scripts_DATA) $(exe_DATA) $(httpdir) 
install-data-hook:
	cp -fr $(httpdir) $(prefix)/http
