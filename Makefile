# the compiler: gcc for C program, define as g++ for C++
CC = g++

# compiler flags:
#  -g     - this flag adds debugging information to the executable file
#  -Wall  - this flag is used to turn on most compiler warnings
CFLAGS  = -g -Wall

# The build target
TARGET = bangheera
SRC = src/
LIB = lib/

all: $(TARGET)

$(TARGET): $(SRC)$(TARGET).cpp
	$(CC) -c $(SRC)$(TARGET).cpp
	$(CC) -o $(SRC)$(TARGET) $(SRC)$(TARGET).o -L$(LIB) -lasmjitd


clean:
	$(RM) $(TARGET)
