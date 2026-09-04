TARGET := esp32c3
OUT_DIR := $(abspath ../../build/firmware/secboot)
KEY := $(OUT_DIR)/test-signing-key.pem
SIGNING_DEFAULTS := $(OUT_DIR)/signing.defaults
PROJECT_DEFAULTS := $(abspath sdkconfig.defaults)

.PHONY: all clean

all: $(KEY) $(SIGNING_DEFAULTS)
	idf.py -B $(OUT_DIR) -D IDF_TARGET=$(TARGET) -D SDKCONFIG=$(OUT_DIR)/sdkconfig '-D SDKCONFIG_DEFAULTS=$(PROJECT_DEFAULTS);$(SIGNING_DEFAULTS)' build

$(KEY):
	mkdir -p $(OUT_DIR)
	espsecure.py generate_signing_key --version 2 $@

$(SIGNING_DEFAULTS): $(KEY)
	printf 'CONFIG_SECURE_BOOT_SIGNING_KEY="%s"\n' "$(KEY)" > $@

clean:
	rm -rf $(OUT_DIR)
