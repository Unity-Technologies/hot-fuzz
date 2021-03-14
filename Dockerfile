FROM ubuntu:16.04

ENV LANG en_US.UTF-8

COPY . /hotfuzz/

WORKDIR /hotfuzz

RUN apt-get update && \
    apt-get -y install software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get -y install \
               python3.6 \
               git \
               build-essential \
               wget \
               locales && rm -rf /var/lib/apt/lists/* && \
    wget -O - https://bootstrap.pypa.io/get-pip.py | python3.6 && \
    sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    dpkg-reconfigure --frontend=noninteractive locales && \
    update-locale LANG=en_US.UTF-8 && \
    git submodule update --init && make -s -C util/radamsa && \
    pip3.6 install . && \
    mkdir results && \
    mkdir /toolkit
