FROM alpine:3.9 as builder
MAINTAINER github@erebe.eu

ARG program_name=memcache_sniffer

RUN apk add --no-cache --repository http://dl-cdn.alpinelinux.org/alpine/v3.6/community \
      git curl musl-dev alpine-sdk cmake libpcap-dev clang
RUN apk add upx --no-cache --repository http://dl-cdn.alpinelinux.org/alpine/edge/community


COPY . /mnt

WORKDIR /mnt
RUN mkdir build
RUN git submodule update --init --recursive

WORKDIR /mnt/build
RUN cmake ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
          -DCMAKE_BUILD_TYPE=Release -DBUILD_STATIC_BINARY=ON
RUN touch ../CMakeLists.txt ; make -j VERBOSE=1
RUN strip --strip-unneeded -s -R .comment -R .gnu.version $program_name
RUN upx --ultra-brute $program_name


FROM alpine:latest as runner
MAINTAINER github@erebe.eu

WORKDIR /root
COPY --from=builder /mnt/build/$program_name .
RUN chmod +x ./$program_name

CMD ["./$program_name"]

