#franksip
AUTOMAKE_OPTIONS=foreign
#CFLAGS = -g -O3 -Wall -DNDEBUG -D__linux__
AM_CFLAGS = -I$(prefix)/include
AM_CPPFLAGS = -I$(prefix)/include

lib_LTLIBRARIES = libfranksip.la
libfranksip_la_SOURCES = sip_authorization.h \
                         sip_contact.h \
                         sip_content_type.h \
                         sip_cseq.h \
                         sip_message.h \
                         sip_params.h \
	                 sip_session_expires.h \
                         sip_supported.h \
                         sip_uri.h \
                         sip_utils.h \
                         sip_via.h \
                         sip_www_authenticate.h \
                         internal.h \
                         osip_list.h \
                         osip_port.h \
                         sdp_message.h \
	                 sip_authorization.c \
                         sip_contact.c \
                         sip_content_type.c \
                         sip_cseq.c \
                         sip_message.c \
                         sip_params.c \
	                 sip_session_expires.c \
                         sip_supported.c \
                         sip_uri.c \
                         sip_via.c \
                         sip_www_authenticate.c \
	                 sip_route.h \
                         sip_route.c \
                         osip_list.c \
                         osip_port.c \
                         sdp_accessor.c \
                         sdp_message.c 
                          

libfranksip_la_CFLAGS = -fPIC
libfranksip_la_LDFLAGS = -version-info 3:0:0
libfranksip_la_LIBADD = -L$(prefix)/lib -lapr-1 -laprutil-1

EXTRA_DIST = libfranksip.vcxproj libfranksip.vcxproj.filters libfranksip.vcxproj.user

