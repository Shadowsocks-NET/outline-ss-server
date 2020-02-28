package metrics

import (
	"testing"
	"time"
)

func TestMethodsDontPanic(t *testing.T) {
	ssMetrics := NewShadowsocksMetrics(nil)
	proxyMetrics := ProxyMetrics{
		ClientProxy: 1,
		ProxyTarget: 2,
		TargetProxy: 3,
		ProxyClient: 4,
	}
	ssMetrics.SetNumAccessKeys(20, 2)
	ssMetrics.AddOpenTCPConnection("US")
	ssMetrics.AddClosedTCPConnection("US", "1", "OK", proxyMetrics, 10*time.Millisecond, 100*time.Millisecond)
	ssMetrics.AddTCPProbe("US", "ERR_CIPHER", "eof", 443, proxyMetrics)
	ssMetrics.AddUDPPacketFromClient("US", "2", "OK", 10, 20, 10*time.Millisecond)
	ssMetrics.AddUDPPacketFromTarget("US", "3", "OK", 10, 20)
	ssMetrics.AddUDPNatEntry()
	ssMetrics.RemoveUDPNatEntry()
}
