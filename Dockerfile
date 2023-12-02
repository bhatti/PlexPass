# Use the official Rust image with version 1.73
FROM rust:1.73 as builder

# Create a new empty shell project
RUN USER=root cargo new --bin plexpass
WORKDIR /plexpass

# Copy the source code of PlexPass into the container
COPY ./ ./

# Build the application in release mode
RUN cargo build --release

# Start a new stage to set up the runtime environment
#FROM debian:bullseye-slim
FROM debian:bookworm-slim

# Install SSL certificates (libssl-dev)
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy the build artifact from the build stage
COPY --from=builder /plexpass/target/release/plexpass /usr/local/bin

# Copy the assets directory
COPY assets /assets

# Create directories for data and certificates
RUN mkdir /data /certs

# Create a volume for the data directory and certs
VOLUME ["/data", "/certs"]

# Expose the ports for HTTP and HTTPS
EXPOSE 8080
EXPOSE 8443

# Set the entrypoint script as the default way to start the container
ENTRYPOINT ["/usr/local/bin/plexpass"]

# Default command is "server"
CMD ["server"]

# Example
#docker run --name plexpass \
#  -e DATA_DIR=/path/to/data \
#  -e DOMAIN=yourdomain.com \
#  -e HSM_PROVIDER=provider_name \
#  -e HTTP_PORT=8080 \
#  -e HTTPS_PORT=8443 \
#  -e DEVICE_PEPPER_KEY=yourdevicepepper \
#  -e JWT_KEY=yourjwtkey \
#  -e HIBP_API_KEY=yourhibpapikey \
#  -e CERT_FILE=/path/to/certfile \
#  -e KEY_FILE=/path/to/keyfile \
#  -e KEY_PASSWORD=yourkeypassword \
#  -v /local/path/data:/data \
#  -v /local/path/certs:/certs \
#  -p 8080:8080 -p 8443:8443 -d plexpass
# Building
#docker build -t plexpass .
#docker run -d -p 8080:8080 -p 8443:8443 plexpass
#docker run --name plexpass -p 8080:8080 -p 8443:8443 -d plexpass server
#docker run -d plexpass -- --master-username xx --master-password xx create-user
#docker run -d -p 8080:8080 -p 8443:8443 plexpass --master-username xx --master-password xx create-user
#docker run -it --entrypoint /bin/bash plexpass
#docker logs plexpass
#docker inspect plexpass
