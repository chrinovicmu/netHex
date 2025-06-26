
CC := clang
CFLAGS := -g -O2 -fsanitize=thread,undefined,alignment
LDFLAGS := -lpcap -pthread
SRC_DIR := src
TARGET := ./main

SRCS := $(wildcard $(SRC_DIR)/*.c)

.PHONY: build run clean perf helgrind git-push

build:
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

run: build
	@echo "Usage: ./main <mode> <filter>"
	@echo "Example: sudo ./main normal \"ip6 tcp\""

clean:
	rm -f $(TARGET)

perf: build
	@echo "RUNNING perf on : $(TARGET)"
	sudo perf stat -e cache-misses,cache-references $(TARGET) > /dev/null 2>&1

helgrind: build
	@echo "RUNNING Helgrind to check for race conditions on : $(TARGET)"
	sudo valgrind --tool=helgrind $(TARGET)

git-push:
	@git add .
	@read -p "commit msg : " msg; \
	git commit -m "$$msg"; \
	git push origin main
