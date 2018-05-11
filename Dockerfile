FROM golang:latest

MAINTAINER Zonesan <chaizs@asiainfo.com>

ENV TIME_ZONE=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TIME_ZONE /etc/localtime && echo $TIME_ZONE > /etc/timezone

COPY . /go/src/github.com/asiainfoldp/sso-auth-proxy

WORKDIR /go/src/github.com/asiainfoldp/sso-auth-proxy

EXPOSE 9090

RUN go build -o sso-proxy

CMD ["./sso-proxy"]
