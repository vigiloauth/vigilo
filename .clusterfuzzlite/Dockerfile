FROM gcr.io/oss-fuzz-base/base-builder-go

ENV PROJECT_NAME vigilo

COPY . $SRC/$PROJECT_NAME/

WORKDIR $SRC/$PROJECT_NAME

COPY .clusterfuzzlite/build.sh $SRC/build.sh

RUN chmod +x $SRC/build.sh