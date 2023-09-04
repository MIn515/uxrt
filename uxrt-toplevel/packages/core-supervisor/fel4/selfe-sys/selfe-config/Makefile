all:
	cargo build --offline --release --features=bin
install-local:
	install -m 755 target/release/selfe $(TOOLS_INSTALL_ROOT)
clean:
	rm -rf target
