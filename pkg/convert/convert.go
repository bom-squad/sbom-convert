package convert

import (
	"context"
	"io"

	"github.com/bom-squad/protobom/pkg/reader"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/bom-squad/protobom/pkg/writer"

	"github.com/bom-squad/go-cli/pkg/domain"
	"github.com/bom-squad/go-cli/pkg/format"
)

var _ domain.ConvertService = (*Service)(nil)

type Service struct {
	Format         *format.Format
	SelectRoot     string
	VirtRootScheme bool
}

func NewService(opts ...Option) *Service {
	s := &Service{}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

type Option func(s *Service)

func (s *Service) Convert(_ context.Context, in io.ReadSeekCloser, out io.WriteCloser) error {
	r := reader.New()
	doc, err := r.ParseStream(in)
	if err != nil {
		return err
	}

	doc = s.HandleMultiRoots(doc)

	w := writer.New()
	w.Options.Format = s.Format.Format

	return w.WriteStream(doc, out)
}

func (s *Service) HandleMultiRoots(doc *sbom.Document) *sbom.Document {
	roots := doc.GetRootNodes()

	if len(roots) > 1 {
		if s.SelectRoot != "" {
			doc = SelectRootScheme(doc, s.SelectRoot)
		}

		if s.VirtRootScheme {
			doc = VirtualRootScheme(doc)
		}
	}

	return doc
}

const (
	VirtualRootDescription = "virtual root scheme, refer roots through dependencies"
	VirtualRootID          = "virutal-root-scheme-id"
)

func SelectRootScheme(doc *sbom.Document, selectRoots string) *sbom.Document {
	for _, root := range doc.GetRootNodes() {
		if selectRoots == root.Id {
			nodeList := doc.GetNodeList()
			nL := nodeList.NodeGraph(root.Id)
			doc.NodeList = nL
			doc.NodeList.RootElements = []string{root.Id}
			return doc
		}
	}

	return doc
}

func VirtualRootScheme(doc *sbom.Document) *sbom.Document {

	doc.NodeList.AddNode(&sbom.Node{
		Id:          VirtualRootID,
		Type:        0,
		Description: VirtualRootDescription,
	})
	doc.NodeList.RootElements = []string{VirtualRootID}

	var ids []string
	for _, root := range doc.GetRootNodes() {
		ids = append(ids, root.Id)
	}

	doc.NodeList.AddEdge(&sbom.Edge{
		Type: 0,
		From: VirtualRootID,
		To:   ids,
	})

	return doc
}
