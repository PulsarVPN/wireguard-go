//go:build !linux

package device

import (
	"github.com/pulsarvpn/wireguard-go/conn"
	"github.com/pulsarvpn/wireguard-go/rwcancel"
)

func (device *Device) startRouteListener(bind conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
