FROM ubuntu:14.04
MAINTAINER Henning Jacobs <henning@jacobs1.de>

RUN apt-get update
RUN apt-get -y install python3-pip
RUN apt-get -y install nmap
RUN apt-get -y install bonnie++ sysbench

ADD requirements.txt /requirements.txt
RUN pip3 install -r /requirements.txt

ADD . /app

ENTRYPOINT ["/app/run.py"]

CMD []
