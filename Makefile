CC = gcc
CFLAGS = -Wall -Wextra -O2
OBJS = website_blocker.o file_helper.o domains_helper.o logging_helper.o ip_helper.o
TARGET = website_blocker

# Default rule: compile everything
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET)

# Compile each .c to .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Run with sudo
run: $(TARGET)
	sudo ./$(TARGET)

# Clean build files
clean:
	rm -f $(OBJS) $(TARGET)
