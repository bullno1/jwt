# Sub-Makefiles
include make/*.mk

# Customizations
PLT_APPS=erts kernel stdlib crypto

# Aggregate all targets
.PHONY: all compile test get-deps release
.DEFAULT_GOAL:=all

all: $(DEFAULT)

compile: $(COMPILE)

test: $(TEST)

clean: $(CLEAN)

get-deps: $(GET_DEPS)

release: $(RELEASE)
