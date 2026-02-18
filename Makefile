CC := g++ -c
LINKER := g++
LDFLAGS := -O2 -L/usr/local/include -lcrypto -lssl -lcurl -lboost_system -lboost_thread
PROJECT_DIR := ${HOME}/Desktop/TorBuster
SRC_DIR := ${PROJECT_DIR}/src
INC_DIR := ${PROJECT_DIR}/includes
HEADERS := ${INC_DIR}/tor_client.hpp ${INC_DIR}/tor_controller.hpp ${INC_DIR}/endpoint_scanner.hpp ${INC_DIR}/utility.hpp
BUILD_DIR := ${PROJECT_DIR}/build

all: torbuster
	rm -rf ${BUILD_DIR}/*.o
	cp ${BUILD_DIR}/torbuster ${HOME}/.local/bin/torbuster
	mkdir ${PROJECT_DIR}/logs

torbuster: endpoint_scanner.o tor_client.o main2.o
	${LINKER} ${BUILD_DIR}/endpoint_scanner.o \
					${BUILD_DIR}/tor_client.o \
					${BUILD_DIR}/main2.o -o ${BUILD_DIR}/torbuster ${LDFLAGS}

endpoint_scanner.o: ${SRC_DIR}/endpoint_scanner.cc ${INC_DIR}/endpoint_scanner.hpp
	mkdir ${PROJECT_DIR}/build
	${CC} ${SRC_DIR}/endpoint_scanner.cc -o ${BUILD_DIR}/endpoint_scanner.o

tor_client.o: ${SRC_DIR}/tor_client.cc ${INC_DIR}/tor_client.hpp
	${CC} ${SRC_DIR}/tor_client.cc -o ${BUILD_DIR}/tor_client.o

main2.o: ${SRC_DIR}/main2.cc
	${CC} ${SRC_DIR}/main2.cc -o ${BUILD_DIR}/main2.o

.PHONY: all clean

clean:
	rm -rf ${BUILD_DIR}/*.o ${BUILD_DIR}/torbuster
