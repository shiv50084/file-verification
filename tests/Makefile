test1_src = local_validation.c $(SRC_DIRS)/validator.c
test1_obj = $(subst .c,.o,$(test1_src))
test1_LD_FLAGS = -lssl -lcrypto
test2_src = remote_validation.c $(SRC_DIRS)/validator.c
test2_obj = $(subst .c,.o,$(test2_src))
test2_LD_FLAGS = -lssl -lcrypto -lcurl

TARGETS := test1 test2

.PHONY: all clean

all: $(TARGETS)

test1: $(test1_obj)
	@$(CC) -o $@ $^ $(test1_LD_FLAGS)

test2: $(test2_obj)
	@$(CC) -o $@ $^ $(test2_LD_FLAGS)

%.o: %.c
	@$(CC) -c $< -o $@ -I "$(INC_DIRS)" $(C_FLAGS)

clean:
	@rm -f *.o
