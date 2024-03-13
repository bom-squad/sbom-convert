package options

import (
	"github.com/spf13/cobra"
)

// ConvertOptions defines the options for the `convert` command
type DiffOptions struct {
	Format     string
	Encoding   string
	OutputPath string
}

// AddFlags adds command line flags for the ConvertOptions struct
func (o *DiffOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.Format, "format", "f", "", "the output format [spdx, spdx-2.3, cyclonedx, cyclonedx-1.0, cyclonedx-1.1, cyclonedx-1.2, cyclonedx-1.3, cyclonedx-1.4, cyclonedx-1.5]") //nolint: lll
	cmd.Flags().StringVarP(&o.Encoding, "encoding", "e", "json", "the output encoding [spdx: [text, json] cyclonedx: [json]")
	cmd.Flags().StringVarP(&o.OutputPath, "output", "o", "", "path to write the diff SBOM")
}
