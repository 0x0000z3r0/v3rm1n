SAMPLES := hello strip secrets secboot

.PHONY: all clean $(SAMPLES)

all: $(SAMPLES)

$(SAMPLES):
	$(MAKE) -C $@

clean:
	for sample in $(SAMPLES); do $(MAKE) -C $$sample clean; done
