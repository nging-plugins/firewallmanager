image="test-ubuntu-firewall-nftables"
docker run --rm -it\
 --workdir /root/go/src/github.com/admpub/nftablesutils\
 --privileged --network=host\
 --entrypoint go\
 -v "$GOPATH/src:/root/go/src" -v "$GOPATH/pkg:/root/go/pkg" $image\
 test -v --count=1 ./biz
