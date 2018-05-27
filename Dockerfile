FROM ubuntu:16.04

RUN apt-get update && \
    apt-get -y install \
               python3 \
               python3-pip \
               git \
               build-essential \
               wget \
               locales && rm -rf /var/lib/apt/lists/*

RUN sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    dpkg-reconfigure --frontend=noninteractive locales && \
    update-locale LANG=en_US.UTF-8

ENV LANG en_US.UTF-8

RUN mkdir -p /hotfuzz/

WORKDIR /hotfuzz

ADD . /hotfuzz/

RUN git submodule update --init && make -s -C util/radamsa

RUN pip3 install -q -r requirements.txt

RUN mkdir results
RUN mkdir /toolkit
