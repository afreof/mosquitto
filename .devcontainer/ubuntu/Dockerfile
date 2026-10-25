# Development environment with everything needed to build all variants of
# mosquitto with make and CMake and to run all its tests, including under
# valgrind and with the sanitizers. Also used by test/podman_ci.py.
FROM docker.io/library/ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        build-essential \
        ca-certificates \
        ccache \
        clang \
        cmake \
        docbook-xsl \
        gdb \
        git \
        lcov \
        libargon2-dev \
        libc-ares-dev \
        libcjson-dev \
        libcunit1-dev \
        libedit-dev \
        libgmock-dev \
        libgtest-dev \
        libmicrohttpd-dev \
        libsqlite3-dev \
        libssl-dev \
        libwebsockets-dev \
        libwrap0-dev \
        microsocks \
        ninja-build \
        openssl \
        pkgconf \
        python3 \
        python3-paho-mqtt \
        python3-psutil \
        sudo \
        uthash-dev \
        valgrind \
        xsltproc && \
    rm -rf /var/lib/apt/lists/*

# The tests must not run as root, because the broker then drops its privileges.
RUN usermod -l dev -d /home/dev -m ubuntu && \
    groupmod -n dev ubuntu && \
    echo 'dev ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/dev
