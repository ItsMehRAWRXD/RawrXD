# RawrXD Validation Harness Makefile
# For MinGW/GCC builds

CC = gcc
CFLAGS = -O2 -Wall -Wextra -I../core -DNDEBUG
LDFLAGS = -L../../build-core -lrawrxd_core -lm

SRCS = rawrxd_validate.c \
       rawrxd_validate_kernels.c \
       rawrxd_validate_gguf.c \
       rawrxd_validate_inference.c \
       rawrxd_validate_stress.c \
       rawrxd_validate_memory.c \
       rawrxd_validate_report.c \
       test_runner.c

OBJS = $(SRCS:.c=.o)
TARGET = ../../build-validation/rawrxd_validate

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p ../../build-validation
	$(CC) $(OBJS) -o $@ $(LDFLAGS)
	@echo "Built: $@"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
	rm -f *.exe

test: $(TARGET)
	$(TARGET) -v

# Individual test targets
test-kernel: $(TARGET)
	$(TARGET) --kernel-only -v

test-full: $(TARGET)
	$(TARGET) -m ../../models/test.gguf -o validation_report -v
