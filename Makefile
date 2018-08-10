CC = gcc
CFLAGS = -g -Wall -fPIC
OBJECTS = http_cookie_extract.o
TARGET = http_cookie_extract.so
MODULES =
INCS =

.cpp.o:  
	$(CC) -c -o $@ $(CFLAGS) $(INCS) $<

.PHONY: all clean
all:$(TARGET)
$(TARGET):$(OBJECTS)
	$(CC) -o $(TARGET) -shared -fPIC $(CFLAGS) $(OBJECTS) $(MODULES)
	
clean:
	rm -rf $(OBJECTS) $(TARGET)