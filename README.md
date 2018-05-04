# ss-example

This repository shows how to implement a custom Shadowsocks server using a [modified version](https://github.com/fortuna/go-shadowsocks2/pull/1) of [go-shadowsocks2](https://github.com/shadowsocks/go-shadowsocks2).

This custom server allows for measuring traffic, and supports multiple users on the same port.

## Try it!

On Terminal 1:
```
git clone -b ss-lib git@github.com:fortuna/go-shadowsocks2.git $(go env GOPATH)/src/github.com/shadowsocks/go-shadowsocks2
git clone git@github.com:fortuna/ss-example.git $(go env GOPATH)/src/github.com/fortuna/ss-example
go get github.com/fortuna/ss-example
go build github.com/fortuna/ss-example
go build github.com/shadowsocks/go-shadowsocks2
```

Start the SS server:
```
./ss-example -u "AEAD_CHACHA20_POLY1305:Secret1" -u "AEAD_CHACHA20_POLY1305:Secret2" -s localhost:9999
```

On Terminal 2, start the SS client:
```
./go-shadowsocks2 -c ss://AEAD_CHACHA20_POLY1305:Secret1@:9999 -verbose  -socks :1080
```

On Terminal 3, fetch a page using the SS client:
```
curl --proxy socks5h://localhost:1080 example.com
```

Stop and restart the client on Terminal 2 with "Secret2" as the password and try to fetch the page again on Terminal 3.


## Performance Testing

Start the iperf3 server (runs on port 5201 by default):
```
iperf3 -s
```

Start the SS server (listening on port 20001):
```
go build github.com/fortuna/ss-example && \
./ss-example -u "AEAD_CHACHA20_POLY1305:Secret1" -s :20001
```

Start the SS tunnel to redirect port 20002 -> localhost:5201 via the proxy on 20001:
```
go build github.com/shadowsocks/go-shadowsocks2 && \
./go-shadowsocks2 -c ss://AEAD_CHACHA20_POLY1305:Secret1@:20001 --tcptun ":20002=localhost:5201" -verbose
```

Run the iperf3 client:
```
iperf3 -c localhost -p 20002
```


### Compare to go-shadowsocks2

Run the commands above, but start the SS server with
```
go build github.com/shadowsocks/go-shadowsocks2 && \
./go-shadowsocks2 -s ss://AEAD_CHACHA20_POLY1305:Secret1@:20001 -verbose
```


### Compare to shadowsocks-libev 

Start the SS server (listening on port 10001):
```
ss-server -s localhost -p 10001 -m chacha20-ietf-poly1305 -k Secret1 -u -v
```

Start the SS tunnel to redirect port 10002 -> localhost:5201 via the proxy on 10001:
```
ss-tunnel -s localhost -p 10001 -m chacha20-ietf-poly1305 -k Secret1 -l 10002 -L localhost:5201 -u -v
```

Run the iperf3 client:
```
iperf3 -c localhost -p 10002
```

You can mix and match the libev and go servers and clients.