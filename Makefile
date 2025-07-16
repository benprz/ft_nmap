#MAKEFLAGS += --silent

CC = gcc
CFLAGS = -Wall -Wextra -Werror -Wpedantic -g
CDEBUGFLAGS = -g
INC_DIR = inc/
INC = ft_nmap.h

EXE = ft_nmap

SRC_DIR = src/
SRC =	main.c \
		ft_nmap.c \
		parsing.c \
		sockets.c \
		tasks.c \
		results.c \
		utils.c

OBJ_DIR = .obj/
OBJ = $(SRC:%.c=$(OBJ_DIR)%.o)

.PHONY : all clean fclean re $(EXE)

all: $(EXE)

$(EXE): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(EXE) -lm -lpcap -lpthread
	@echo "------------"

$(OBJ_DIR)%.o: $(SRC_DIR)%.c $(addprefix $(INC_DIR),$(INC))
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@ -I $(INC_DIR)

run:
	./$(EXE) host

strace: $(EXE)
	strace ./$(EXE) host

container:
	docker build . -t ft_nmap
	docker run -d --rm --cap-add=NET_ADMIN --network host -v ./:/shared --name ft_nmap ft_nmap

shell:
	docker exec -it ft_nmap /bin/bash

rm_container:
	docker container prune

clean:
	@/bin/rm -rf $(OBJ_DIR)

fclean: clean
	@/bin/rm -f $(EXE)

re:
	$(MAKE) fclean
	$(MAKE) all
