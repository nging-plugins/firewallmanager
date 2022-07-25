image="test-ubuntu-firewall"
if [ "$1" != "" ]; then
    image="$1"
fi
docker run --rm -it\
 --workdir /root/go/src/github.com/admpub/gerberos\
 --privileged\
 --entrypoint go\
 -v "$GOPATH/src:/root/go/src" $image\
 run cmd/gerberos/main.go\
 -c ./gerberos.toml
