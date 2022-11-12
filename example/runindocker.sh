image="test-ubuntu-firewall"
if [ "$1" != "" ]; then
    image="$1"
fi
docker run --rm -it\
 --workdir /root/go/src/github.com/nging-plugins/firewallmanager/example\
 --privileged\
 --network host\
 -v "$GOPATH/src:/root/go/src" -v "$GOPATH/src:$GOPATH/src" $image
