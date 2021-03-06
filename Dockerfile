FROM docker.io/ubuntu:18.04

ENV TZ="CST-8" \
    tag="localhost" \
    cache="4096" \
    session="4096" \
    timeout="3600" \
    debug="off" \
    http_filter_code="400,404,304" \
    http_filter_type="audio/,video/,image/,font/,application/pdf,application/msword,application/javascript,text/javascript,text/css"

COPY src /root/sensor

RUN apt-get -y update && \
    apt-get -y install software-properties-common wget && \
    wget -q http://apt-stable.ntop.org/18.04/all/apt-ntop-stable.deb && \
    dpkg -i apt-ntop-stable.deb && \
    apt-get clean all && \
    apt-get -y update && \
    apt-get -y install pfring && \
    DEBIAN_FRONTEND="noninteractive" apt-get -y install tshark && \
    apt-get -y install libpcap-dev && \
    apt-get -y install python3 python3-pip python3-lxml && \
    pip3 install cacheout && \
    pip3 install pyshark && \
    pip3 install requests && \
    pip3 install pypcap && \
    pip3 install dpkt && \
    pip3 install brotli && \
    chmod 750 /usr/bin/dumpcap && \
    chgrp root /usr/bin/dumpcap && \
    apt-get clean all && \
    apt-get autoclean && \
    apt-get autoremove && \
    rm -f apt-ntop-stable.deb

ENTRYPOINT ["/bin/bash","-c","/usr/bin/python3 /root/sensor/main.py -i $interface -t $tag -s $ip -p $port -c $cache -S $session -T $timeout -d $debug"]