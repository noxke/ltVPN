# 指定编译器
CC = gcc

# 编译选项
CFLAGS = -Iinclude -Wall

# 链接选项
LDFLAGS = -lssl -lcrypto

# 源文件目录
SRC_DIR = src

# 头文件目录
INC_DIR = include

# 目标文件目录
BUILD_DIR = build

# 搜索所有的源文件
SRCS = $(wildcard $(SRC_DIR)/*.c)
SRCS_SERVER = $(wildcard $(SRC_DIR)/server/*.c)
SRCS_CLIENT = $(wildcard $(SRC_DIR)/client/*.c)

# 将源文件名替换为目标文件名
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))
OBJS_SERVER = $(patsubst $(SRC_DIR)/server/%.c, $(BUILD_DIR)/server/%.o, $(SRCS_SERVER))
OBJS_CLIENT = $(patsubst $(SRC_DIR)/client/%.c, $(BUILD_DIR)/client/%.o, $(SRCS_CLIENT))

# 可执行文件名
TARGET_SERVER = ltvpn-server
TARGET_CLIENT = ltvpn-client

# 默认目标
all: $(BUILD_DIR) $(TARGET_SERVER) $(TARGET_CLIENT)

server: $(BUILD_DIR) $(TARGET_SERVER)

client: $(BUILD_DIR) $(TARGET_CLIENT)

# 创建build目录
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/server
	mkdir -p $(BUILD_DIR)/client

# 链接可执行文件
$(TARGET_SERVER): $(OBJS) $(OBJS_SERVER)
	$(CC) -o $@ $^ $(LDFLAGS)

$(TARGET_CLIENT): $(OBJS) $(OBJS_CLIENT)
	$(CC) -o $@ $^ $(LDFLAGS)

# 编译源文件生成目标文件
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/server/%.o: $(SRC_DIR)/server/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/client/%.o: $(SRC_DIR)/client/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理生成的文件
clean:
	rm -rf $(BUILD_DIR) $(TARGET_SERVER) $(TARGET_CLIENT)

.PHONY: all clean