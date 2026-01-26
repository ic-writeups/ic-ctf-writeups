FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
        socat busybox net-tools iproute2 resolvconf \
        && rm -rf /var/lib/apt/lists/*

RUN mkdir /home/ctf
WORKDIR /home/ctf
RUN useradd -M -d /ctf ctf

RUN echo "Connection blocked" > /etc/banner_fail
COPY ./chall /home/ctf
RUN cat /dev/urandom | head -c 32 > /tmp/x
RUN echo "r00t{$(md5sum /tmp/x|cut -d ' ' -f1)}" > flag.txt
#COPY ./flag.txt /home/ctf
COPY ./serve.sh serve
RUN chown -R root:ctf /home/ctf && \
        chmod -R 750 /home/ctf

EXPOSE 1235
ENTRYPOINT ["./serve"]
