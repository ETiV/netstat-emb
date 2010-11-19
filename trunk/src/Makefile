CC=gcc
STRIP=strip
OPTS=-Wall -static
ENDIANESS=0
#ENDIANESS=1
TARGET=netstat-emb

$(TARGET):
	$(CC) -DENDIANESS=$(ENDIANESS) $(TARGET).c -o $(TARGET) $(OPTS)
	$(STRIP) $(TARGET)

clean:
	rm -f $(TARGET)
