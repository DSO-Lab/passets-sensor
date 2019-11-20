#FROM harbor.shuziguanxing.com/pad/passets:1.0.0
FROM docker.io/ubuntu:18.04

MAINTAINER rH.5@shuziguanxing

COPY src /root/passets

RUN apt-get update 
RUN sh -c "/bin/echo -e yes\n"|apt-get -y install tshark && \
	apt-get -y install python3 python3-pip python3-lxml && \
	pip3 install cacheout && \
	pip3 install pyshark && \
	chmod 750 /usr/bin/dumpcap && \
	chgrp root /usr/bin/dumpcap && \
	apt-get clean && \
	apt-get autoclean && \
	apt-get autoremove


ENTRYPOINT ["/bin/bash","-c","/usr/bin/python3 /root/passets/main.py -i $interface -t $tag -s $ip -p $port -r $switch -d $debug"]