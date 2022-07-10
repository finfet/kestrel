FROM ubuntu:20.04

ARG APP_VERSION

RUN apt-get update && \
 apt-get upgrade -y && \
 DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential devscripts \
 debhelper fakeroot bash-completion cargo

RUN mkdir /build

WORKDIR /build

COPY --chmod=644 build/kestrel-$APP_VERSION.tar.gz .

RUN cp kestrel-$APP_VERSION.tar.gz kestrel_$APP_VERSION.orig.tar.gz

RUN tar -xf kestrel-$APP_VERSION.tar.gz && cd kestrel-$APP_VERSION && debuild --no-lintian -us -uc -rfakeroot -b
