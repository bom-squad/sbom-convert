package convert

import (
	"github.com/bom-squad/go-cli/pkg/format"
)

func WithFormat(f *format.Format) Option {
	return func(s *Service) {
		s.Format = f
	}
}

func WithSelectRoot(selectRoot string) Option {
	return func(s *Service) {
		s.SelectRoot = selectRoot
	}
}

func WithVirtualRootScheme(virtRootScheme bool) Option {
	return func(s *Service) {
		s.VirtRootScheme = virtRootScheme
	}
}
