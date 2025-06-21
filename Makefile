CC = gcc
FLAGS = -MMD -Iinclude
CFLAGS = -g -Wall -Wextra -O2
LDFLAGS =

BUILD_DIR = build
SRC_DIR = src

$(BUILD_DIR)/%_c.o : $(SRC_DIR)/%.c
	mkdir -p $(@D)
	$(CC) $(FLAGS) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/%_S.o : $(SRC_DIR)/%.S
	mkdir -p $(@D)
	$(CC) $(FLAGS) $(CFLAGS) -c -o $@ $<

C_SRCS = $(shell find $(SRC_DIR) -type f -name "*.c")
ASM_SRCS = $(shell find $(SRC_DIR) -type f -name "*.S")

C_OBJS = $(C_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%_c.o)
ASM_OBJS = $(ASM_SRCS:$(SRC_DIR)/%.S=$(BUILD_DIR)/%_S.o)

OBJS = $(C_OBJS) $(ASM_OBJS)

DEPS = $(OBJS:%.o=%.d)
-include $(DEPS)

$(BUILD_DIR)/app.elf : $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

.PHONY: clean all

clean:
	rm -rf $(BUILD_DIR)

all: $(BUILD_DIR)/app.elf