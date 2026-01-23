FROM node:18-alpine

# Metadata
LABEL maintainer="Solid Community Server Docker Image Maintainer <thomas.dupont@ugent.be>"

# Create writable directories
RUN mkdir /config /data

# Set working directory
WORKDIR /community-server

# Copy everything AS-IS (no build step)
COPY . .

# Expose Solid port
EXPOSE 3000

# Default Solid file storage config
ENV CSS_CONFIG=config/file.json
ENV CSS_ROOT_FILE_PATH=/data

# Run Solid Community Server with BASE_URL from env
CMD sh -c 'if [ -z "$BASE_URL" ]; then echo "ERROR: BASE_URL is not set" && exit 1; fi && node bin/server.js -c config/file.json -f /data --baseUrl "$BASE_URL"'
