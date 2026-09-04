TARGET := esp32c3
OUT_DIR := $(abspath ../../build/firmware/secrets)

.PHONY: all clean

all:
	mkdir -p $(OUT_DIR)
	idf.py -B $(OUT_DIR) -D IDF_TARGET=$(TARGET) -D SDKCONFIG=$(OUT_DIR)/sdkconfig build

clean:
	rm -rf $(OUT_DIR)
