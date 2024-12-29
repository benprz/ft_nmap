FROM debian:latest

RUN apt update && apt install -y netbase iproute2 openssh-server gcc make tshark vim nmap

WORKDIR /shared

RUN echo "service ssh start && ip a && tail -f" > /script.sh

EXPOSE 22

CMD ["sh", "/script.sh"]
