image="test-ubuntu-firewall"
if [ "$1" != "" ]; then
    image="test-ubuntu-firewall-$1" # test-ubuntu-firewall-nftables
fi
docker run --rm -it\
 --workdir /root/go/src/github.com/nging-plugins/firewallmanager/example\
 --privileged\
 -p "28181:28181"\
 -v "$GOPATH/src:/root/go/src" -v "$GOPATH/pkg:/root/go/pkg" -v "$GOPATH/src:$GOPATH/src" -v "$GOPATH/pkg:$GOPATH/pkg" $image
# 在容器内通过 host.docker.internal 访问宿主机