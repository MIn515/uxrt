# Standard things

sp 		:= $(sp).x
dirstack_$(sp)	:= $(d)
d		:= $(dir)

GENXRFS := $(EXTERNAL_PKG_ROOT)/xrfs/genxrfs/genxrfs

#XXX: there is probably a better way to do this
$(PLATFORM_OBJ)/tests/dummy_mapped: $(d)/dummy_mapped.S
	(grep -q '\.code64' $< && $(TEST_MODULE_ASSEMBLE64)) || $(TEST_MODULE_ASSEMBLE32)
$(PLATFORM_OBJ)/tests/%: $(d)/%.S
	(grep -q '\.code64' $< && $(TEST_KERNEL_ASSEMBLE64)) || $(TEST_KERNEL_ASSEMBLE32)


$(PLATFORM_OBJ)/tests/%.boot:	$(PLATFORM_OBJ)/tests/% $(PLATFORM_OBJ)/tests/dummy_mapped
	mkdir -p $(PLATFORM_OBJ)/tests/contents/$*/boot/boot
	echo 'dummy unmapped module' > $(PLATFORM_OBJ)/tests/contents/$*/boot/boot/@dummy,m
	ln -f $< $(PLATFORM_OBJ)/tests/contents/$*/boot/boot/@kernel,110000,100000,k
	ln -f $(PLATFORM_OBJ)/tests/dummy_mapped $(PLATFORM_OBJ)/tests/contents/$*/boot/boot/@dummy_exec,auto,100000,x
	$(GENXRFS) -o 'BOS loader test image: $(basename $<)' -v $@ $(PLATFORM_OBJ)/tests/contents/$*/boot

$(PLATFORM_OBJ)/tests/%.iso:	$(PLATFORM_OBJ)/tests/%.boot $(PLATFORM_OBJ)/mb2_img_loader 
	rm -rf $(PLATFORM_OBJ)/tests/contents/$*/iso
	cp -R $(PLATFORM_SRC)/tests/skel $(PLATFORM_OBJ)/tests/contents/$*/iso
	ln $^ $(PLATFORM_OBJ)/tests/contents/$*/iso
	echo DEFAULT $* > $(PLATFORM_OBJ)/tests/contents/$*/iso/isolinux/isolinux.cfg
	echo LABEL $* >> $(PLATFORM_OBJ)/tests/contents/$*/iso/isolinux/isolinux.cfg
	echo " KERNEL /isolinux/mboot.c32" >> $(PLATFORM_OBJ)/tests/contents/$*/iso/isolinux/isolinux.cfg		
	echo " APPEND /mb2_img_loader --- /`basename $<`" >> $(PLATFORM_OBJ)/tests/contents/$*/iso/isolinux/isolinux.cfg
	genisoimage -o $@ -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -l $(PLATFORM_OBJ)/tests/contents/$*/iso

OBJDIRS := $(OBJDIRS) $(PLATFORM_OBJ)/tests

TEST_TARGETS := $(TARGETS) \
	   	$(PLATFORM_OBJ)/tests/fail_bad_address_size.iso \
		$(PLATFORM_OBJ)/tests/fail_bad_arch.iso \
		$(PLATFORM_OBJ)/tests/fail_bad_checksum.iso \
		$(PLATFORM_OBJ)/tests/fail_bad_magic.iso \
		$(PLATFORM_OBJ)/tests/fail_multiple_tags.iso \
		$(PLATFORM_OBJ)/tests/fail_no_header.iso \
		$(PLATFORM_OBJ)/tests/fail_unaligned_header.iso \
		$(PLATFORM_OBJ)/tests/fail_unknown_request.iso \
		$(PLATFORM_OBJ)/tests/fail_unknown_tag_type.iso \
		$(PLATFORM_OBJ)/tests/fail_unsupported_env.iso \
		$(PLATFORM_OBJ)/tests/success_32.iso \
		$(PLATFORM_OBJ)/tests/success_64.iso

TEST_CLEAN := $(TEST_CLEAN) $(TEST_TARGETS)
CLEAN := $(CLEAN) $(TEST_CLEAN)

# Standard things

d		:= $(dirstack_$(sp))
sp		:= $(basename $(sp))
