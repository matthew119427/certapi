FROM golang:latest

WORKDIR /usr/src/certificateapi

COPY . .

ENV GIN_MODE=release

RUN make
RUN cp build/certificateapi /usr/local/bin/certapi

CMD ["/usr/local/bin/certapi"]
