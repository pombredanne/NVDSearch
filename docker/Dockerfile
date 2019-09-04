# NVD Search Server Build

FROM ubuntu:18.04

RUN apt-get update && apt-get install -y \
        python3 \
        python3-pip \
&& rm -rf /var/lib/apt/lists/*

RUN pip3 install requests
RUN pip3 install colorama

ADD nvdsearch.py /
ADD config /

# Entrypoint
ADD entrypoint.sh /
CMD /entrypoint.sh
