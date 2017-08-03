test1_src = local_validation.c $(SRC_DIRS)/validator.c
test1_obj = $(subst .c,.o,$(test1_src))

TARGETS := test1

.PHONY: all clean

all: test1

test1: $(test1_obj)
	@$(CC) -o $@ $^

%.o: %.c
	@$(CC) -c $< -o $@ -I "$(INC_DIRS)" $(C_FLAGS)

clean:
	@rm -f *.o
