##
##  Makefile -- Build procedure for sample mod_authn_any Apache module
##  Autogenerated via ``apxs -n mod_authn_any -g''.
##

builddir=.
top_srcdir=/usr/share/apache2
top_builddir=/usr/share/apache2
include /usr/share/apache2/build/special.mk

#   the used tools
APACHECTL=apachectl

#   additional defines, includes and libraries
#DEFS=-Dmy_define=my_value
#INCLUDES=-Imy/include/dir
#LIBS=-Lmy/lib/dir -lmylib

#   the default target
all: local-shared-build

#   install the shared object file into Apache 
install: install-modules-yes
	cp authn_any.load /etc/apache2/mods-available
	a2enmod authn_any

#   cleanup
clean:
	-rm -f mod_authn_any.o mod_authn_any.lo mod_authn_any.slo mod_authn_any.la 

#   simple test
test: reload
	lynx -mime_header http://localhost/mod_authn_any

#   install and activate shared object by reloading Apache to
#   force a reload of the shared object file
reload: install restart

#   the general Apache start/restart/stop
#   procedures
start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop
