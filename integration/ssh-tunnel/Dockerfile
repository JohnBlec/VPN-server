FROM alpine:3.22
RUN apk add --no-cache openssh-client
COPY start.sh /start.sh
ENTRYPOINT ["/bin/sh", "/start.sh"]
