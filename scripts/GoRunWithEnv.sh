#!/bin/bash
echo "## $0 received NUM ARGS : " $#
APP_REPOSITORY=github.com/lao-tseu-is-alive/go-cloud-k8s-employe-jwt
NOW=$(date +%Y-%m-%dT%T)
REVISION="$(git describe --dirty --always)"
LDFLAGS="-X ${APP_REPOSITORY}/pkg/version.BuildStamp=${NOW} -X ${APP_REPOSITORY}/pkg/version.REVISION=${REVISION}"
ENV_FILENAME='.env'
if [ $# -eq 1 ]; then
  GO_MAIN_FILENAME=${1}
elif [ $# -eq 2 ]; then
  GO_MAIN_FILENAME=${1}
  ENV_FILENAME=${2:='.env'}
else
  echo "## 💥💥 expecting first argument to be path to your Go main and second argument an  .env file name"
  exit 1
fi
echo "## will try to run : ${GO_MAIN_FILENAME} with env variables in ${ENV_FILENAME} ..."
if [ -r "$ENV_FILENAME" ]; then
  if [ -r "$GO_MAIN_FILENAME" ]; then
    echo "## will do : go run $LDFLAGS $GO_MAIN_FILENAME"
    set -a
    source <(sed -e '/^#/d;/^\s*$/d' -e "s/'/'\\\''/g" -e "s/=\(.*\)/='\1'/g" $ENV_FILENAME )
    go run -ldflags "$LDFLAGS" "${GO_MAIN_FILENAME}"
    set +a
  else
    echo "## 💥💥 expecting first argument to be an executable path"
    exit 1
  fi
else
  echo "## 💥💥 env path argument : ${ENV_FILENAME} was not found"
  exit 1
fi
