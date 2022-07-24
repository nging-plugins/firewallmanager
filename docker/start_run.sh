image="test-ubuntu-firewall"
if [ "$1" != "" ]; then
    image="$1"
fi
docker run --rm -it\
 --privileged\
 --entrypoint go\
 -p "18080:8080" -v "$GOPATH/src:/root/go/src" $image\
 run -tags="sqlite" . -c /myconfig/config.yaml -p 8080