CXX := g++ 
OPTIONS := -std=c++17 -O3 -Wall -pedantic

all: hij

hij: hij.o
	$(CXX) $(OPTIONS) hij.o -o hij

hij.o:
	$(CXX) $(OPTIONS) -c hij.cpp

clean:
	rm -rf *.o hij

