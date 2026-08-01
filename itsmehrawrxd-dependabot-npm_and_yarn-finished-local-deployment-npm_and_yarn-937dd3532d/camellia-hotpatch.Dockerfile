# RawrZ Camellia Hot-Patch System
# Provides encrypted runtime patching with hardware ID spoofing

# ----------  stage 1: build static camellia + patch stub ----------
FROM alpine:latest as camellia
RUN apk add --no-cache clang lld musl-dev git cmake openssl-dev

WORKDIR /build

# Clone Linux kernel for Camellia implementation
RUN git clone --depth 1 https://github.com/torvalds/linux.git && \
    cp linux/crypto/camellia.c . && \
    cp linux/include/crypto/camellia.h .

# Copy patch stub and supporting files
COPY stub_patch.c .
COPY spoof_descriptors.c .
COPY camellia_hotpatch.h .

# Compile Camellia implementation
RUN clang -O3 -c camellia.c -o camellia.o

# Compile patch stub
RUN clang -O3 -c stub_patch.c -o stub.o

# Compile spoof descriptors
RUN clang -O3 -c spoof_descriptors.c -o spoof.o

# Create spoof descriptor binary blob
RUN echo -e "VOLUME_SERIAL:12345678\nMAC_ADDRESS:00:11:22:33:44:55\nSMBIOS_UUID:12345678-1234-1234-1234-123456789abc\nHDD_FIRMWARE:WD1234567890" > spoof_desc.bin

# Link everything into a static executable
RUN ld.lld -r -b binary -o spoof_blob.o spoof_desc.bin
RUN clang -nostdlib -static -O3 -o patchstub.elf \
        camellia.o stub.o spoof.o spoof_blob.o -fuse-ld=lld

# ----------  stage 2: serve stage ----------
FROM alpine:latest
RUN apk add --no-cache python3 py3-pip nodejs npm curl wget

# Install additional tools
RUN apk add --no-cache \
    gcc \
    g++ \
    make \
    cmake \
    nasm \
    yasm \
    clang \
    lld \
    musl-dev \
    linux-headers \
    binutils \
    mingw-w64-gcc \
    mingw-w64-crt \
    mingw-w64-winpthreads \
    openssl-dev

WORKDIR /app

# Copy compiled patch stub
COPY --from=camellia /build/patchstub.elf /usr/local/bin/
COPY --from=camellia /build/spoof_desc.bin /usr/local/bin/

# Copy scripts and server
COPY apply_patch.sh /usr/local/bin/apply_patch.sh
COPY pack_camellia.py /usr/local/bin/pack_camellia.py
COPY camellia-hotpatch-server.js /app/server.js
COPY package.json /app/

# Make scripts executable
RUN chmod +x /usr/local/bin/apply_patch.sh
RUN chmod +x /usr/local/bin/pack_camellia.py

# Install Node.js dependencies
RUN npm install

# Create output directory
RUN mkdir -p /app/output

EXPOSE 8080
CMD ["node", "server.js"]
