# Build Stage
FROM ubuntu:latest AS build

# Update and install necessary build tools
RUN apt update && apt install -y \
    curl unzip git wget python3 python3-pip build-essential \
    && wget https://go.dev/dl/go1.22.1.linux-amd64.tar.gz \
    && rm -rf /usr/local/go && tar -C /usr/local -xzf go1.22.1.linux-amd64.tar.gz \
    && rm -f go1.22.1.linux-amd64.tar.gz \
    && apt clean && rm -rf /var/lib/apt/lists/*

# Set environment variables for Go
ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin:/usr/local/go/bin:$HOME/.local/bin"
ENV GOROOT="/usr/local/go"
ENV GOPATH="/root/go"

# Install Python dependencies without cache

# Install Go tools
RUN GO111MODULE=on go install github.com/jaeles-project/gospider@latest
RUN go install github.com/tomnomnom/gf@latest && go install github.com/tomnomnom/qsreplace@latest
 
    
RUN git clone https://github.com/tomnomnom/gf /root/gfcl/
RUN mv /root/gfcl/examples/ /root/.gf/
RUN git clone https://github.com/1ndianl33t/Gf-Patterns /root/gf-patterns/
RUN mv /root/gf-patterns/*.json /root/.gf/

# Runtime Stage (final smaller image using Python slim)
FROM python:3.12-slim

# Copy Go binaries and tools from the build stage
COPY --from=build /usr/local/go /usr/local/go
COPY --from=build /root/go/bin /root/go/bin
COPY --from=build /root/.gf/ /root/.gf/

# The shared class is built from this repository, not from the published
# release: a worker that calls auth_headers(task) against a release that
# does not have it fails inside the scan.  scripts/build_workers.sh passes
# the local wheel; the default is the published release.
ARG B_HUNTERS_WHEEL=b-hunters==1.4.1
RUN pip install --no-cache-dir ${B_HUNTERS_WHEEL} uro

# Set environment variables for Go
ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin:/usr/local/go/bin:$HOME/.local/bin"
ENV GOROOT="/usr/local/go"
ENV GOPATH="/root/go"


# Copy necessary files
COPY spider.sh /app/spider.sh
RUN chmod +x /app/spider.sh
COPY spider spider

# Default command
CMD ["python3", "-m", "spider"]
