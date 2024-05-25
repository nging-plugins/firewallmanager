image="test-ubuntu-firewall"
driver="iptables"
if [ "$1" != "" ]; then
    image="$1"
fi
if [ "$1" == "test-ubuntu-firewall-nftables" ]; then
    driver="nftables"
fi
docker run --rm -it\
 --workdir /root/go/src/github.com/nging-plugins/firewallmanager\
 --privileged --network=host\
 --entrypoint go\
 -v "$GOPATH/src:/root/go/src" -v "$GOPATH/pkg:/root/go/pkg" $image\
 test -v --count=1 ./application/library/driver/$driver
