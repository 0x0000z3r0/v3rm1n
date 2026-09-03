CC := gcc
CFLAGS := -Wall -Wextra -pedantic -std=c11
LDLIBS := -lm -lcrypto -lelf -ljson-c
SRC := $(wildcard *.c)
OUT_DIR := ../build/scanner
OUT := $(OUT_DIR)/v3rm1n
LOGO_SRC := $(OUT_DIR)/logo-data.c

.PHONY: all clean

all: $(OUT)

$(OUT): $(SRC) $(wildcard *.h) $(LOGO_SRC)
	mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LOGO_SRC) $(LDLIBS)

$(LOGO_SRC): ../media/logo.txt
	mkdir -p $(OUT_DIR)
	xxd -i -n logo_data $< > $@

clean:
	rm -rf $(OUT_DIR)
