# Reproducible environment for both Tailscale v1.104.1 PoCs.
# Build (from the reports/ directory):
#   docker build -f env/Dockerfile -t ts-pocs .
# Run:
#   docker run --rm ts-pocs
FROM golang:1.27-bookworm
WORKDIR /pocs
COPY taildrive-symlink-escape/poc/ /pocs/taildrive/
COPY webclient-rebind-control-repoint/poc/ /pocs/webclient/
COPY env/run_all.sh /pocs/run_all.sh
RUN chmod +x /pocs/run_all.sh \
 && cd /pocs/taildrive  && go mod download \
 && cd /pocs/webclient  && go mod download
ENTRYPOINT ["/pocs/run_all.sh"]
