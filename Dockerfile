FROM node:18-alpine

# Metadata
LABEL maintainer="Solid Community Server Docker Image Maintainer <thomas.dupont@ugent.be>"

# Create config & data dirs
RUN mkdir /config /data

# Set working directory
WORKDIR /community-server

# Copy everything AS-IS (no build)
COPY . .

# Expose Solid port
EXPOSE 3000

# Default Solid file storage config
ENV CSS_CONFIG=config/file.json
ENV CSS_ROOT_FILE_PATH=/data

# Run Solid Community Server (file mode)
CMD ["node", "bin/server.js"]
