# ss-example

This repository shows how to implement a custom Shadowsocks server using a [modified version](https://github.com/fortuna/go-shadowsocks2/pull/1) of [go-shadowsocks2](https://github.com/shadowsocks/go-shadowsocks2).

This custom server allows for measuring traffic using [prometheus.io](https://prometheus.io), and supports multiple users on the same port.

## Try it!

Clone the repositories:
```
git clone -b ss-lib https://github.com/fortuna/go-shadowsocks2.git $(go env GOPATH)/src/github.com/shadowsocks/go-shadowsocks2 &&
git clone https://github.com/fortuna/ss-example.git $(go env GOPATH)/src/github.com/fortuna/ss-example
```

For development, you may want to use SSH:
```
git clone -b ss-lib git@github.com:fortuna/go-shadowsocks2.git $(go env GOPATH)/src/github.com/shadowsocks/go-shadowsocks2 &&
git clone git@github.com:fortuna/ss-example.git $(go env GOPATH)/src/github.com/fortuna/ss-example
```

Fetch dependencies and build:
```
go get github.com/fortuna/ss-example github.com/shadowsocks/go-shadowsocks2 github.com/prometheus/prometheus/cmd/...
```

On Terminal 1, start the SS server:
```
./ss-example -u "chacha20-ietf-poly1305:Secret1" -u "chacha20-ietf-poly1305:Secret2" -s localhost:9999 -metrics localhost:8080
```

On Terminal 2, start prometheus scraper for metrics collection:
```
$(go env GOPATH)/bin/prometheus --config.file=prometheus_example.yml
```

On Terminal 3, start the SS client:
```
./go-shadowsocks2 -c ss://chacha20-ietf-poly1305:Secret1@:9999 -verbose  -socks :1080
```

On Terminal 4, fetch a page using the SS client:
```
curl --proxy socks5h://localhost:1080 example.com
```

Stop and restart the client on Terminal 3 with "Secret2" as the password and try to fetch the page again on Terminal 4.

Open http://localhost:8080/metrics and see the exported Prometheus variables.

Open http://localhost:9090/ and see the Prometheus server dashboard.


## Performance Testing

Start the iperf3 server (runs on port 5201 by default):
```
iperf3 -s
```

Start the SS server (listening on port 20001):
```
go build github.com/fortuna/ss-example && \
./ss-example -u "chacha20-ietf-poly1305:Secret1" -s :20001
```

Start the SS tunnel to redirect port 20002 -> localhost:5201 via the proxy on 20001:
```
go build github.com/shadowsocks/go-shadowsocks2 && \
./go-shadowsocks2 -c ss://chacha20-ietf-poly1305:Secret1@:20001 -tcptun ":20002=localhost:5201" -udptun ":20002=localhost:5201" -verbose
```

Test TCP upload (client -> server):
```
iperf3 -c localhost -p 20002
```

Test TCP download (server -> client):
```
iperf3 -c localhost -p 20002 --reverse
```

Test UDP upload:
```
iperf3 -c localhost -p 20002 --udp -b 0
```

Test UDP download:
```
iperf3 -c localhost -p 20002 --udp -b 0 --reverse
```

### Compare to go-shadowsocks2

Run the commands above, but start the SS server with
```
go build github.com/shadowsocks/go-shadowsocks2 && \
./go-shadowsocks2 -s ss://chacha20-ietf-poly1305:Secret1@:20001 -verbose
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

Run the iperf3 client tests listed above on port 10002.

You can mix and match the libev and go servers and clients.
