image="test-ubuntu-firewall"
if [ "$1" != "" ]; then
    image="$1"
fi
docker run --rm -it --privileged -p "18080:8080" -v "$GOPATH/src:/root/go/src" -v "$GOPATH/pkg:/root/go/pkg" $image -run.appendParams "-c /myconfig/config.yaml"