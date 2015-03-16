all:
	cd src && make && cd ..

install_all:
	mkdir -p /usr/lib
	mkdir -p /usr/include/psec
	cp src/libpsec.so /usr/lib/
	cp -r include/* /usr/include/psec/

clean:
	cd src && make clean && cd ..
	cd example && make clean && cd ..

