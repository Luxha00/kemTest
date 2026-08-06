# POPRAVEK: osnova zamenjana iz Alpine (musl libc) v Ubuntu 24.04 LTS,
# da se ujema z okoljem, opisanim v poglavju 4 naloge, in da se izognemo
# morebitnim razlikam v obnašanju standardne knjižnice med musl in glibc.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Namesti potrebna orodja
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        g++ \
        make \
        cmake \
        ninja-build \
        git \
        ca-certificates \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Kloniraj in zgradi liboqs (Open Quantum Safe)
#
# POPRAVEK: prejšnja različica ni podajala NOBENIH prevajalniških
# zastavic, kar pomeni, da je bil liboqs zgrajen s privzetimi
# nastavitvami (generična arhitektura, brez -O3). Poglavje 4 naloge pa
# eksplicitno navaja zastavice -DOQS_DIST_BUILD=OFF, -march=native in
# -O3 - te zdaj dejansko uporabimo, da build ustreza opisu v nalogi.
#
# OPOMBA: -march=native med gradnjo slike (build) prilagodi kodo
# arhitekturi stroja, na katerem se slika GRADI. Če se slika gradi na
# drugem stroju kot tistem, na katerem se izvajajo meritve, to lahko
# povzroči nezdružljivost (SIGILL) ali generira kodo, ki ne izkorišča
# vseh razpoložljivih ukaznih naborov ciljnega stroja. Za dosledno
# reprodukcijo naloge sliko zgradite NEPOSREDNO na isti VM/arhitekturi
# (Intel Cascade Lake), na kateri boste pognali meritve.
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs && \
    cd liboqs && mkdir build && cd build && \
    cmake -GNinja \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_BUILD_TYPE=Release \
        -DOQS_DIST_BUILD=OFF \
        -DCMAKE_C_FLAGS="-march=native" \
        .. && \
    ninja -j$(nproc) && ninja install && \
    ldconfig

# Kopiraj vse datoteke iz trenutne mape (gostitelja) v /app v kontejnerju
COPY . /app
WORKDIR /app

# Zgradi C++ program
#
# POPRAVEK: prej brez -O2/-O3/-march=native (privzeto torej -O0).
# Neoptimizirana gradnja testnega ogrodja sicer ne spremeni izmerjenih
# ciklov *znotraj* klicev v liboqs, lahko pa vnese dodaten, nepotreben
# šum v okoliško kodo (npr. alokacijo medpomnilnikov), zato jo
# poravnamo z enakimi zastavicami kot liboqs.
RUN g++ -O3 -march=native -o kem_test main.cpp \
        -I/usr/local/include -L/usr/local/lib \
        -loqs -lssl -lcrypto -lpthread

# OPOMBA O IZVAJANJU MERITEV:
# Ta Docker slika je namenjena PONOVLJIVI GRADNJI programa, ne nujno
# tudi izvajanju samih časovnih meritev. Poglavje 4 naloge opisuje
# meritve na golem Ubuntu 24.04 LTS VM-u z izoliranimi jedri (GRUB
# isolcpus + cset) in `taskset -c 4` - te ravni izolacije Docker privzeto
# NE zagotavlja (cgroups, namespace overhead). Za dejanske meritve
# priporočamo:
#   1) zgraditi sliko in binarko (`docker build .`),
#   2) binarko `kem_test` kopirati/izvesti NEPOSREDNO na izoliranem
#      gostitelju (izven kontejnerja) z `taskset -c <izolirano_jedro>`,
#      kot je opisano v poglavju 4.
# Če je zagon znotraj kontejnerja nujen, uporabite vsaj
# `docker run --cpuset-cpus=<jedro> --privileged ...`, kar pa še vedno
# ne odpravi popolnoma dodatnega navideznega sloja Dockerja.

CMD ["./kem_test"]
