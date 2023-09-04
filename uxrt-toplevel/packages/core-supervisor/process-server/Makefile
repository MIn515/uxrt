.PHONY: all install

CPU=x86_64
PLATFORM=pc99

all:
	mkdir -p artifacts/debug
	RUSTFLAGS="-Z macro-backtrace" selfe build --platform "$(PLATFORM)" --sel4_arch "$(CPU)"
	ln -f target/sel4-build/kernel/kernel.elf artifacts/debug/kernel
	ln -f target/$(CPU)-sel4-fel4/debug/uxrt-process-server artifacts/debug/proc
	strip -o artifacts/debug/kernel.stripped artifacts/debug/kernel
	strip -o artifacts/debug/proc.stripped artifacts/debug/proc
clean:
	rm -rf artifacts target
