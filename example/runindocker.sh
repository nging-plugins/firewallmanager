image="test-ubuntu-firewall"
if [ "$1" != "" ]; then
    image="$1"
fi
docker run --rm -it\
 --workdir /root/go/src/github.com/nging-plugins/firewallmanager/example\
 --privileged\
 -p "28181:28181"\
 -v "$GOPATH/src:/root/go/src" -v "$GOPATH/src:$GOPATH/src" $image
# 在容器内通过 host.docker.internal 访问宿主机