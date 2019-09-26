ALL: haredns_def.hpp haredns.cpp haredns_sec.hpp
	clang++ -o run -std=c++17 haredns.cpp -lcrypto

run: ALL
	./run verisigninc.com

mydig: mydig.cpp haredns_def.hpp
	clang++ -o mydig -std=c++17 mydig.cpp

release:
	mkdir -p build && \
    cd build       && \
    conan install .. --build=missing --profile ../build-profile && \
    cmake .. -DCMAKE_BUILD_TYPE=Release && \
    cmake --build .
