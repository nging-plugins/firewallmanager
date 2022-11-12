image="test-ubuntu-firewall"
if [ "$1" != "" ]; then
    image="$1"
fi
docker run --rm -it\
 --workdir /root/go/src/github.com/nging-plugins/firewallmanager/example\
 --privileged\
 -p "18181:18181"\
 -v "$GOPATH/src:/root/go/src" $image
