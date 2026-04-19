CC = g++
CFLAGS = -std=c++11 -Wall -Wextra -Iinclude -I/usr/local/include
LDFLAGS = -lcurl

TARGET = libnss_oslogin.so

SRCS = ncc/ncc_oslogin.cc ncc/oslogin_utils.cc
OBJS = $(SRCS:.cc=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

%.o: %.cc
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)