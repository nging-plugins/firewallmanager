image="test-ubuntu-firewall"
if [ "$1" != "" ]; then
    image="$1"
fi
docker run --rm -it\
 --workdir /root/go/src/github.com/nging-plugins/firewallmanager\
 --privileged\
 --entrypoint go\
 -v "$GOPATH/src:/root/go/src" $image\
 test -v --count=1 ./pkg/library/driver/iptables
