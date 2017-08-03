CUR_DIR = $(CURDIR)

export PROJECT_ROOT := $(CUR_DIR)
export INC_DIRS := $(CUR_DIR)/include
export SRC_DIRS := $(CUR_DIR)/src

export CC := clang
export C_FLAGS := -std=c11

TEST_DIR := tests/

all: $(TEST_DIR)

$(TEST_DIR):
	@$(MAKE) -C $@ $(MAKECMDGOALS)

clean: $(TEST_DIR)
	@rm -f $(SRC_DIRS)/*.o
