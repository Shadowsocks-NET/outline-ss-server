# Outline ss-server

This repository has the Shadowsocks service soon to be used by Outline servers. It's based on a [modified version](https://github.com/shadowsocks/go-shadowsocks2/pull/100) of [go-shadowsocks2](https://github.com/shadowsocks/go-shadowsocks2), with a number of improvements to meet the needs of the Outline users.

The Outline version of the go-shaowsocks2 service allows for:
- Multiple users on a single port.
  - Does so by trying all the different credentials until one succeeds.
- Multiple ports
- Whitebox monitoring of the service using [prometheus.io](https://prometheus.io)
  - Includes traffic measurements and other health indicators.
- Live updates via config change + SIGHUP

![Graphana Dashboard](https://user-images.githubusercontent.com/113565/44177062-419d7700-a0ba-11e8-9621-db519692ff6c.png "Graphana Dashboard")

## Try it!

Clone the repositories:
```
git clone -b ss-lib https://github.com/fortuna/go-shadowsocks2.git $(go env GOPATH)/src/github.com/shadowsocks/go-shadowsocks2 &&
git clone https://github.com/Jigsaw-Code/outline-ss-server.git $(go env GOPATH)/src/github.com/Jigsaw-Code/outline-ss-server
```

For development, you may want to use SSH:
```
git clone -b ss-lib git@github.com:fortuna/go-shadowsocks2.git $(go env GOPATH)/src/github.com/shadowsocks/go-shadowsocks2 &&
git clone git@github.com:Jigsaw-Code/outline-ss-server.git $(go env GOPATH)/src/github.com/Jigsaw-Code/outline-ss-server
```

Fetch dependencies and build:
```
go get github.com/Jigsaw-Code/outline-ss-server github.com/shadowsocks/go-shadowsocks2 github.com/prometheus/prometheus/cmd/...
```

On Terminal 1, start the SS server:
```
$(go env GOPATH)/bin/outline-ss-server -config config_example.yml -metrics localhost:8080
```

On Terminal 2, start prometheus scraper for metrics collection:
```
$(go env GOPATH)/bin/prometheus --config.file=prometheus_example.yml
```

On Terminal 3, start the SS client:
```
$(go env GOPATH)/bin/go-shadowsocks2 -c ss://chacha20-ietf-poly1305:Secret0@:9000 -verbose  -socks :1080
```

On Terminal 4, fetch a page using the SS client:
```
curl --proxy socks5h://localhost:1080 example.com
```

Stop and restart the client on Terminal 3 with "Secret1" as the password and try to fetch the page again on Terminal 4.

Open http://localhost:8080/metrics and see the exported Prometheus variables.

Open http://localhost:9090/ and see the Prometheus server dashboard.


## Performance Testing

Start the iperf3 server (runs on port 5201 by default):
```
iperf3 -s
```

Start the SS server (listening on port 9000):
```
go build github.com/Jigsaw-Code/outline-ss-server && \
./outline-ss-server -config config_example.yml
```

Start the SS tunnel to redirect port 8000 -> localhost:5201 via the proxy on 9000:
```
go build github.com/shadowsocks/go-shadowsocks2 && \
./go-shadowsocks2 -c ss://chacha20-ietf-poly1305:Secret0@:9000 -tcptun ":8000=localhost:5201" -udptun ":8000=localhost:5201" -verbose
```

Test TCP upload (client -> server):
```
iperf3 -c localhost -p 8000
```

Test TCP download (server -> client):
```
iperf3 -c localhost -p 8000 --reverse
```

Test UDP upload:
```
iperf3 -c localhost -p 8000 --udp -b 0
```

Test UDP download:
```
iperf3 -c localhost -p 8000 --udp -b 0 --reverse
```

### Compare to go-shadowsocks2

Run the commands above, but start the SS server with
```
go build github.com/shadowsocks/go-shadowsocks2 && \
./go-shadowsocks2 -s ss://chacha20-ietf-poly1305:Secret0@:9000 -verbose
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
