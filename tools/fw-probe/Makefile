PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
CC := $(PS5_PAYLOAD_SDK)/bin/prospero-clang
CFLAGS := -Wall -Wextra -O2 -g
LDFLAGS := -lkernel_web -lSceLibcInternal -lSceNet -lSceSystemService -lSceSysmodule

TARGET := fw-probe.elf

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
