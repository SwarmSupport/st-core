package proxyserver

import (
	"io"
	"net"
)

func relay(client, upstream net.Conn) {
	done := make(chan struct{}, 2)
	copyConnection := func(destination, source net.Conn) {
		_, _ = io.Copy(destination, source)
		if writer, ok := destination.(interface{ CloseWrite() error }); ok {
			_ = writer.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyConnection(upstream, client)
	go copyConnection(client, upstream)
	<-done
	_ = client.Close()
	_ = upstream.Close()
	<-done
}
