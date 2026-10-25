# Development environment with musl libc, like the Docker images in docker/,
# with everything needed to build mosquitto with make and CMake and to run its
# tests, including under valgrind. Also used by test/podman_ci.py.
FROM docker.io/library/alpine:3.23

# cjson-static: the CMake build looks for cJSON with find_package(cJSON), which
# needs the cJSON CMake files that Alpine only ships with the static library.
RUN apk --no-cache add \
        argon2-dev \
        bash \
        build-base \
        ccache \
        cjson-dev \
        cjson-static \
        cmake \
        cunit-dev \
        docbook-xsl \
        gdb \
        git \
        gtest-dev \
        libedit-dev \
        libmicrohttpd-dev \
        libwebsockets-dev \
        libxslt \
        linux-headers \
        openssl \
        openssl-dev \
        pkgconf \
        py3-paho-mqtt \
        py3-psutil \
        python3 \
        samurai \
        sqlite-dev \
        sudo \
        uthash-dev \
        util-linux-dev \
        valgrind

# The tests must not run as root, because the broker then drops its privileges.
RUN adduser -D -u 1000 -s /bin/bash dev && \
    echo 'dev ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/dev
