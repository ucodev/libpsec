all:
	cd src && make && cd ..

clean:
	cd src && make clean && cd ..
	cd example && make clean && cd ..

