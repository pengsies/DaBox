CC ?= cc
UNAME_S := $(shell uname -s)
COMMON_CFLAGS := -O2 -g0 -fno-omit-frame-pointer -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wall -Wextra -Wconversion -Wformat=2 -Wformat-security -Werror=implicit-function-declaration

ifeq ($(UNAME_S),Linux)
  CFLAGS := $(COMMON_CFLAGS) -fPIE -fstack-clash-protection -fcf-protection=full
  LDFLAGS := -pie -Wl,-z,relro,-z,now,-z,noexecstack
else
  CFLAGS := $(COMMON_CFLAGS)
  LDFLAGS :=
endif

.PHONY: all clean
all: relay-worker

relay-worker: relay-worker.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f relay-worker
