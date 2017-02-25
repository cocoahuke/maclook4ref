CC=clang
CFLAGS=-fobjc-arc -fobjc-link-runtime -framework Foundation src/libcapstone.a

build/maclook4ref:
	mkdir -p build;
	$(CC) $(CFLAGS) src/*.m -o $@

.PHONY:install
install:build/maclook4ref
	mkdir -p /usr/local/bin
	cp build/maclook4ref /usr/local/bin/maclook4ref

.PHONY:uninstall
uninstall:
	rm /usr/local/bin/maclook4ref

.PHONY:clean
clean:
	rm -rf build
