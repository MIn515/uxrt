STAGE_ROOT := process-server/artifacts/debug
SUBARCH := generic
all:
	cd boot && make
	cd process-server && make
clean:
	cd boot && make clean
	cd process-server && make clean
install-local:
	cd boot && make install-local
	#TODO: once UX/RT supports a full root filesystem, just copy the kernel to boot/$(SUBARCH)/kernel without the address (the image builder will handle the kernel address)
	rm -rf "$(INSTALL_ROOT)/contents/boot/$(SUBARCH)/"@kernel,*
	rm -rf "$(INSTALL_ROOT)/contents/boot/$(SUBARCH)/"@proc,*
	install -D -m 644 $(STAGE_ROOT)/kernel.stripped "$(INSTALL_ROOT)/contents/boot/$(SUBARCH)/@kernel,`../xrfs/genxrfs/xrfsaddr $(STAGE_ROOT)/kernel`,k"
	install -D -m 644 $(STAGE_ROOT)/proc.stripped "$(INSTALL_ROOT)/contents/boot/$(SUBARCH)/@proc,`../xrfs/genxrfs/xrfsaddr -a $(STAGE_ROOT)/proc`,x"
	install -D -m 644 test.txt "$(INSTALL_ROOT)/contents/test.txt"
