#! /bin/bash

docker kill -s 2 $(docker ps | grep "hot-fuzz" | awk '{print $1}')
