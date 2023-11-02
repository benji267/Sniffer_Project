# Compiler
CC = gcc
CFLAGS = -Wall -g -I$(INC_DIR)

# Bibliothèque PCAP
LIBS = -lpcap

# Fichiers source
SRC_DIR = src
SRC_FILES = $(wildcard $(SRC_DIR)/*.c)

# Fichiers objets
OBJ_DIR = obj
OBJ_FILES = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRC_FILES))

# Exécutable
EXECUTABLE = analyseur

# Fichiers header
INC_DIR = include
INC_FILES = $(wildcard $(INC_DIR)/*.h)

# Règle par défaut
all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJ_FILES)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(INC_FILES)
	$(CC) $(CFLAGS) -c -o $@ $<

# Règle clean pour nettoyer les fichiers objets et l'exécutable
clean:
	rm -f $(OBJ_DIR)/*.o $(EXECUTABLE)
