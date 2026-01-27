//go:build !darwin && !windows && !linux

package ime

import "errors"

// OtherPlatform is a stub for unsupported platforms.
type OtherPlatform struct{}

func NewOtherPlatform(config PlatformConfig, engine *Engine) *OtherPlatform {
	return &OtherPlatform{}
}

func (p *OtherPlatform) Name() string {
	return "unsupported"
}

func (p *OtherPlatform) Available() bool {
	return false
}

func (p *OtherPlatform) Install() error {
	return errors.New("IME not supported on this platform")
}

func (p *OtherPlatform) Uninstall() error {
	return errors.New("IME not supported on this platform")
}

func (p *OtherPlatform) IsInstalled() bool {
	return false
}

func (p *OtherPlatform) IsActive() bool {
	return false
}

func (p *OtherPlatform) Activate() error {
	return errors.New("IME not supported on this platform")
}

var _ Platform = (*OtherPlatform)(nil)
