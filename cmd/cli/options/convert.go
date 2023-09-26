package options

import (
	"github.com/spf13/cobra"
)

// ConvertOptions defines the options for the `convert` command
type ConvertOptions struct {
	Format         string
	Encoding       string
	OutputPath     string
	SelectRoot     string
	VirtRootScheme bool
}

// AddFlags adds command line flags for the ConvertOptions struct
func (o *ConvertOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.Format, "format", "f", "", "the output format [spdx, spdx-2.3, cyclonedx, cyclonedx-1.4]")
	cmd.Flags().StringVarP(&o.Encoding, "encoding", "e", "json", "the output encoding [spdx: [text, json] cyclonedx: [json]")
	cmd.Flags().StringVarP(&o.OutputPath, "output", "o", "", "path to write the converted SBOM")
	cmd.Flags().StringVarP(&o.SelectRoot, "select-root", "r", "", "select root id")
	cmd.Flags().BoolVarP(&o.VirtRootScheme, "virtual-root", "", false, "enable virtual root for multi targets")

}
