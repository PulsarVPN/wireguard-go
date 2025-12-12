//go:build !linux

package device

import (
	"github.com/PulsarVPN/wireguard-go/conn"
	"github.com/PulsarVPN/wireguard-go/rwcancel"
)

func (device *Device) startRouteListener(bind conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
