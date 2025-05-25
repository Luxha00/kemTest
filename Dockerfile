# Uporabi lightweight Alpine Linux kot osnovo
FROM alpine:latest

# Posodobi pakete in namesti potrebna orodja
RUN apk update && apk upgrade && \
    apk add --no-cache \
    g++ \
    make \
    cmake \
    git \
    bash

# Kloniraj in zgradi liboqs (Open Quantum Safe)
RUN git clone https://github.com/open-quantum-safe/liboqs && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    make -j$(nproc) && make install

# Kopiraj vse datoteke iz trenutne mape (gostitelja) v /app v kontejnerju
COPY . /app
WORKDIR /app

# Zgradi C++ program ob zagonu kontejnerja (opcijsko)
RUN g++ -o kem_test main.cpp -loqs -L/usr/local/lib -I/usr/local/include