FROM ghcr.io/l3yx/sandbox:latest

USER root

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ffuf \
    gobuster \
    whatweb \
    wfuzz \
    ripgrep \
    tcpdump \
    zip \
    gdb \
    strace \
    ltrace \
    socat \
    patchelf \
    mono-complete \
    python3-docx \
    python3-pwntools \
    python3-z3 \
    python3-sympy \
    unzip \
    && rm -rf /var/lib/apt/lists/*

ARG YSOSERIAL_VERSION=v1.36
ARG YSOSERIAL_ASSET=ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9.zip
ARG NUCLEI_VERSION=3.6.2
ARG SUBFINDER_VERSION=2.10.1
ARG FEROXBUSTER_VERSION=2.13.0

RUN mkdir -p /opt/ysoserial \
    && curl -fsSL \
        "https://github.com/pwntester/ysoserial.net/releases/download/${YSOSERIAL_VERSION}/${YSOSERIAL_ASSET}" \
        -o /tmp/ysoserial.zip \
    && python3 -c "from zipfile import ZipFile; ZipFile('/tmp/ysoserial.zip').extractall('/opt/ysoserial')" \
    && printf '%s\n' \
        '#!/bin/sh' \
        'exec mono /opt/ysoserial/Release/ysoserial.exe "$@"' \
        > /usr/local/bin/ysoserial \
    && chmod 0755 /usr/local/bin/ysoserial \
    && rm -f /tmp/ysoserial.zip

RUN tmpdir="$(mktemp -d)" \
    && cd "$tmpdir" \
    && curl -fsSL \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
        -o nuclei.zip \
    && unzip nuclei.zip \
    && install -m 0755 nuclei /usr/local/bin/nuclei \
    && cd / \
    && rm -rf "$tmpdir"

RUN tmpdir="$(mktemp -d)" \
    && cd "$tmpdir" \
    && curl -fsSL \
        "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" \
        -o subfinder.zip \
    && unzip subfinder.zip \
    && install -m 0755 subfinder /usr/local/bin/subfinder \
    && cd / \
    && rm -rf "$tmpdir"

RUN tmpdir="$(mktemp -d)" \
    && cd "$tmpdir" \
    && curl -fsSL \
        "https://github.com/epi052/feroxbuster/releases/download/v${FEROXBUSTER_VERSION}/x86_64-linux-feroxbuster.zip" \
        -o feroxbuster.zip \
    && unzip feroxbuster.zip \
    && install -m 0755 feroxbuster /usr/local/bin/feroxbuster \
    && cd / \
    && rm -rf "$tmpdir"

USER ubuntu
