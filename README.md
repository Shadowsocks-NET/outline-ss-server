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