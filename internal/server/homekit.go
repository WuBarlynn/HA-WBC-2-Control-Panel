package server

import (
	"encoding/base64"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/skip2/go-qrcode"

	"ha-wbc-console/internal/homekit"
	"ha-wbc-console/internal/store"
)

type homeKitStatusResponse struct {
	homekit.Status
	QRCode string `json:"qrCode,omitempty"`
}

func (s *Server) handleHomeKitStatus(w http.ResponseWriter, r *http.Request) {
	if s.homekit == nil {
		fail(w, http.StatusServiceUnavailable, "HomeKit 服务未初始化")
		return
	}
	status := s.homekit.Status()
	response := homeKitStatusResponse{Status: status}
	if status.Enabled && status.Running && !status.Paired && status.SetupURI != "" {
		png, err := qrcode.Encode(status.SetupURI, qrcode.Medium, 320)
		if err == nil {
			response.QRCode = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
		}
	}
	ok(w, response)
}

func (s *Server) handleHomeKitConfigure(w http.ResponseWriter, r *http.Request) {
	if s.homekit == nil {
		fail(w, http.StatusServiceUnavailable, "HomeKit 服务未初始化")
		return
	}
	var body struct {
		Enabled bool   `json:"enabled"`
		Name    string `json:"name"`
		Pin     string `json:"pin"`
		Port    int    `json:"port"`
	}
	if err := readBody(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	cfg := store.HomeKitConfig{
		Enabled: body.Enabled,
		Name:    body.Name,
		Pin:     body.Pin,
		Port:    body.Port,
	}
	if err := s.homekit.Configure(cfg, requestIP(r)); err != nil {
		var configErr *homekit.ConfigError
		var portErr *homekit.PortError
		switch {
		case errors.As(err, &configErr):
			fail(w, http.StatusBadRequest, err.Error())
		case errors.As(err, &portErr):
			fail(w, http.StatusConflict, err.Error())
		default:
			log.Printf("[homekit] 更新配置失败: %v", err)
			fail(w, http.StatusInternalServerError, "HomeKit 服务配置失败,请查看日志")
		}
		return
	}
	s.handleHomeKitStatus(w, r)
}

func requestIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(strings.Trim(host, "[]"))
}

func (s *Server) handleHomeKitReset(w http.ResponseWriter, r *http.Request) {
	if s.homekit == nil {
		fail(w, http.StatusServiceUnavailable, "HomeKit 服务未初始化")
		return
	}
	if err := s.homekit.ResetPairings(requestIP(r)); err != nil {
		log.Printf("[homekit] 重置配对失败: %v", err)
		fail(w, http.StatusInternalServerError, "HomeKit 配对重置失败,请查看日志")
		return
	}
	s.handleHomeKitStatus(w, r)
}
