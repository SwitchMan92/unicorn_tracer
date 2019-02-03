FROM ubuntu:latest

RUN apt update
RUN apt upgrade -y
RUN apt install -y python python-dev python-pip qemu

COPY ./requirements.txt /var/
RUN pip install -r /var/requirements.txt
COPY . /var/unicorn_tracer
WORKDIR /var/unicorn_tracer
CMD ["python", "-m", "unittest", "discover"]