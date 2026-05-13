CXX      = g++
CXXFLAGS = -Wall -Wextra -O3 -std=c++17 -I$(SRC_DIR)
LDLIBS   = -lcrypto

SRC_DIR = src
BIN_DIR = build/bin
OBJ_DIR = build/obj

SRCS    = $(shell find $(SRC_DIR) -name '*.cpp')
OBJS    = $(SRCS:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)
DEPS    = $(OBJS:.o=.d)
TARGET  = $(BIN_DIR)/rootfs

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) | $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -MMD -MP -c -o $@ $<

$(BIN_DIR):
	mkdir -p $@

-include $(DEPS)

clean:
	$(RM) -r $(OBJ_DIR) $(BIN_DIR)
