ALL: haredns_def.hpp haredns.cpp haredns_sec.hpp
	clang++ -o run -std=c++17 haredns.cpp -lcrypto

run: ALL
	./run google.com

mydig: mydig.cpp haredns_def.hpp
	clang++ -o mydig -std=c++17 mydig.cpp
