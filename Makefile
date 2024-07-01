# Makefile

SUBDIRS := unpatched_mitm_communicators patched_mitm_communicators
SUBDIRSCLEAN=$(addsuffix clean,$(SUBDIRS))

.DEFAULT_GOAL := all
all: pnc_mitm_pe.bin pnc_mitm_ppe.bin $(SUBDIRS) 

$(SUBDIRS):
	$(MAKE) -C $@

%.bin: %.c 
	${CC} $^ -o $@

clean: $(SUBDIRSCLEAN)
	rm -f *.o *.bin 

%clean: %
	$(MAKE) -C $< clean

.PHONY: all $(SUBDIRS)
