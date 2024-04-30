FROM gcr.io/oss-fuzz-base/base-builder-go
RUN git clone --depth 1 https://github.com/bytemare/opaque.git
COPY . $SRC/opaque
WORKDIR $SRC/opaque
COPY ./.clusterfuzzlite/build.sh $SRC/