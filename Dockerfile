FROM debian:stable
ARG BINARY

RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY target/release/$BINARY /usr/local/bin/ldap_server
ENTRYPOINT ["/usr/local/bin/ldap_server"]
