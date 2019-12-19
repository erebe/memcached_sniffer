FROM alpine:3.9 as builder
MAINTAINER github@erebe.eu

ARG program_name=memcache_sniffer

RUN apk add --no-cache --repository http://dl-cdn.alpinelinux.org/alpine/v3.9/community \
      git curl musl-dev alpine-sdk cmake libpcap-dev clang zlib-dev curl-dev
COPY . /mnt

WORKDIR /mnt
RUN mkdir build
RUN git submodule update --init --recursive

# Building promtheus-cpp librairie
WORKDIR /mnt/deps/prometheus-cpp
RUN mkdir _build
WORKDIR /mnt/deps/prometheus-cpp/_build
RUN cmake .. -DBUILD_SHARED_LIBS=OFF
RUN make -j
RUN mkdir -p deploy
RUN make DESTDIR=$(pwd)/deploy install

WORKDIR /mnt/build
RUN cmake ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
          -DCMAKE_BUILD_TYPE=Release -DBUILD_STATIC_BINARY=ON
RUN touch ../CMakeLists.txt ; make -j VERBOSE=1
RUN strip --strip-unneeded -s -R .comment -R .gnu.version $program_name


FROM alpine:latest as runner
MAINTAINER github@erebe.eu

ARG program_name=memcache_sniffer

RUN adduser -h /home/sniffer -D -g '' sniffer
WORKDIR /home/sniffer
COPY --from=builder /mnt/build/$program_name .

RUN apk add --no-cache libcap ;\
    chmod +x ./$program_name ;\
    setcap cap_net_raw,cap_net_admin=eip ./$program_name

USER sniffer

CMD ["./memcache_sniffer"]

