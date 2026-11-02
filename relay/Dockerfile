FROM gogost/gost:3.3.2@sha256:25648f4aeb4f3a0511e941449229f815802e38ba14394bc5f644629cce0f7a3c
RUN apk add --no-cache python3 tini \
    && addgroup -S wgproxy \
    && adduser -S -G wgproxy wgproxy
WORKDIR /app
COPY start-relay.sh gost_config.py /app/
USER wgproxy
EXPOSE 8080
ENTRYPOINT ["/sbin/tini", "-g", "--"]
CMD ["/bin/sh", "/app/start-relay.sh"]
