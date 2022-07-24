FROM ubuntu:latest

ENV GO_VERSION 1.18.4
ENV GO_INSTALL_FILE go${GO_VERSION}.linux-amd64.tar.gz

RUN apt update
RUN apt upgrade -y
RUN apt install wget -y

#RUN wget -c https://studygolang.com/dl/golang/${GO_INSTALL_FILE}
RUN wget -c https://golang.google.cn/dl/${GO_INSTALL_FILE}
RUN tar zxvf ${GO_INSTALL_FILE}
RUN ln -s /go/bin/go /usr/local/bin/go
RUN ln -s /go/bin/gofmt /usr/local/bin/gofmt
RUN rm -rf /${GO_INSTALL_FILE}

VOLUME ["/root/go"]

ENTRYPOINT ["/usr/local/bin/go"]
CMD ["env"]
