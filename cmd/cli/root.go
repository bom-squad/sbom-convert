package cli

import (
	"fmt"
	"os"

	mcobra "github.com/muesli/mango-cobra"
	"github.com/muesli/roff"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/bom-squad/sbom-convert/cmd/cli/options"
	"github.com/bom-squad/sbom-convert/pkg/log"
)

var (
	version = "0.0.0-dev"
	name    = "sbom-convert"
)

func ManCommand(root *cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "man",
		Short:                 "Generates command line manpages",
		SilenceUsage:          true,
		DisableFlagsInUseLine: true,
		Hidden:                true,
		Args:                  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			manPage, err := mcobra.NewManPage(1, root)
			if err != nil {
				return err
			}

			_, err = fmt.Fprint(os.Stdout, manPage.Build(roff.NewDocument()))
			return err
		},
	}

	return cmd
}

func NewRootCmd() *cobra.Command {
	ro := &options.RootOptions{}
	rootCmd := &cobra.Command{
		Use:     "sbom-convert",
		Version: version,
		Short:   "Convert between CycloneDX into SPDX SBOM",
		Long:    "Convert between CycloneDX into SPDX SBOM, Bridging the gap between CycloneDX and SPDX",
		Run:     func(cmd *cobra.Command, args []string) {},
		CompletionOptions: cobra.CompletionOptions{
			HiddenDefaultCmd: true,
		},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := validateRootOptions(ro); err != nil {
				return err
			}

			if err := options.BindConfig(viper.GetViper(), cmd); err != nil {
				return err
			}
			return setupLogger(ro)
		},
		SilenceErrors: true,
	}

	rootCmd.SetVersionTemplate(fmt.Sprintf("%s v{{.Version}}\n", name))

	ro.AddFlags(rootCmd)

	// Commands
	cvtCmd := ConvertCommand()
	rootCmd.AddCommand(cvtCmd)

	// Commands
	diffCmd := DiffCommand()
	rootCmd.AddCommand(diffCmd)

	// Manpages
	rootCmd.AddCommand(ManCommand(rootCmd))
	return rootCmd
}

func validateRootOptions(_ *options.RootOptions) error {
	return nil
}

func setupLogger(ro *options.RootOptions) error {
	level := zapcore.Level(int(zap.WarnLevel) - ro.Verbose)
	log, err := log.NewLogger(
		log.WithLevel(level),
		log.WithGlobalLogger(),
	)
	if err != nil {
		return err
	}

	log.Debug("logger initialized")
	return nil
}
