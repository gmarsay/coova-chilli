## Process this file with automake to produce Makefile.in

chillidir = $(sysconfdir)/chilli

wwwdir = $(chillidir)/www

dist_www_DATA = coova.html coova.jpg wait.gif
nodist_www_DATA = config.sh

EXTRA_DIST = config.sh.in

edit = sed \
	-e 's,@SBINDIR\@,$(sbindir),g' \
	-e 's,@INITDIR\@,$(sysconfdir)/init.d,g' \
	-e 's,@VARRUN\@,$(localstatedir)/run,g' \
	-e 's,@ETCCHILLI\@,$(sysconfdir)/chilli,g' \
	-e 's,@SYSCONFDIR\@,$(sysconfdir),g' \
	-e 's,@PREFIX\@,$(prefix),g'

config.sh: Makefile config.sh.in
	rm -f config.sh config.sh.tmp
	$(edit) config.sh.in >config.sh.tmp
	mv config.sh.tmp config.sh
