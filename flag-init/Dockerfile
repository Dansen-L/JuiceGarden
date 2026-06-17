FROM alpine:3.19

RUN apk add --no-cache python3

COPY mint_flags.py /mint_flags.py

VOLUME ["/flag-data"]

CMD ["python3", "/mint_flags.py"]
