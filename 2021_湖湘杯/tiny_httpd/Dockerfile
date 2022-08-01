FROM ubuntu:18.04
MAINTAINER A_Dog
ENV REFRESHED_AT 2020-09-30
ENV LANG C.UTF-8


#new user
RUN useradd -m ctf
WORKDIR /home/ctf

#copy file
COPY ./httpd /home/ctf/
COPY ./flag /home/ctf/
COPY ./htdocs/* /home/ctf/htdocs/
RUN chmod +x /home/ctf/httpd

EXPOSE 9999
CMD /home/ctf/httpd 9999


#sudo docker build -t tiny_httpd ./
#sudo docker run -p 9999:9999 tiny_httpd
#sudo docker run -p 9999:9999  -it tiny_httpd  /bin/sh
