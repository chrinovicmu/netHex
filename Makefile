
CC := clang
CFLAGS := -O2 -fsanitize=thread,undefined,alignment 
#-Wall -Wpedantic -Wextra -Wno-Wunused-parameter,function,variable -fsanitize=undefined,thread,alignment 
LDFLAGS := -lpcap -pthread
SRC_DIR := src
TARGET := ./main

SRCS := $(wildcard $(SRC_DIR)/*.c)

PF := 

.PHONY: build run clean

build:
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

run: build
	sudo $(TARGET) $(PF)

clean:
	rm -f $(TARGET)

perf: build 
	@echo "RUNNING perf on : $(TARGET)"
	sudo perf stat -e cache-misses,cache-references $(TARGET) > /dev/null 2>&1

helgrind: build
	@echo "RUNNING Helgrind to check for race conditions on : $(TARGET)"
	sudo valgrind --tool=helgrind $(TARGET) $(PF)
.PHONY: git-push 
git-push:
	@git add .
	@read -p "commit msg : " msg; \
	git commit -m "$$msg"; \
	git push origin main 

