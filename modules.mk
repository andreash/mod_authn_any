mod_authn_any.la: mod_authn_any.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_authn_any.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_authn_any.la
