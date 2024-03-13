package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/bom-squad/sbom-convert/cmd/cli/options"
	"github.com/bom-squad/sbom-convert/pkg/diff"
	"github.com/bom-squad/sbom-convert/pkg/format"
)

func DiffCommand() *cobra.Command {
	co := &options.DiffOptions{}
	c := &cobra.Command{
		Use:        "diff",
		Aliases:    []string{"df"},
		SuggestFor: []string{"diff"},
		Short:      "Diff between two SBOMS, agnostic to format CycloneDX and SPDX SBOMs",
		Long:       `Diff between two SBOMS, agonstic to format CycloneDX and SPDX.`,
		Example: `
sbom-diff diff sbom_1.cdx.json  sbom_2.cdx.json                           output to stdout in inverse format
sbom-diff diff sbom_1.spdx.json sbom_2.cdx.json -o sbom.cdx.json          output to a file
sbom-diff diff sbom_1.cdx.json sbom_2.cdx.json -f spdx-2.3         		  select to a specific format
sbom-diff diff sbom_1.cdx.json sbom_2.cdx.json -f spdx -e text   	      select specific encoding
	 				`,
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		Args:              cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiff(cmd.Context(), co, args)
		},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := cmd.Parent().PersistentPreRunE(cmd.Parent(), args); err != nil {
				return err
			}

			if err := options.BindConfig(viper.GetViper(), cmd); err != nil {
				return err
			}

			return validateDiffOptions(co, args)
		},
	}

	co.AddFlags(c)

	return c
}

func validateDiffOptions(_ *options.DiffOptions, _ []string) error {
	return nil
}

// runDiff is the main entrypoint for the `diff` command
func runDiff(ctx context.Context, co *options.DiffOptions, args []string) error {
	log := zap.S()
	log.Info("Running Diff command ...")
	path1 := args[0]
	path2 := args[1]

	f1, err := os.Open(path1)
	if err != nil {
		return err
	}
	defer f1.Close()

	f2, err := os.Open(path2)
	if err != nil {
		return err
	}
	defer f2.Close()

	output_frmt, err := parseFormatNoInverse(co.Format, co.Encoding, f1)
	if err != nil {
		return err
	}
	log.Debugf("Output format %s", output_frmt)

	df1, err := format.Detect(f1)
	if err != nil {
		return err
	}

	log.Debugf("First '%s' format '%s'", path1, df1)

	df2, err := format.Detect(f1)
	if err != nil {
		return err
	}
	log.Debugf("Second '%s' format '%s'", path2, df2)

	overwrited := true
	out1, outPath1, err := createOutputStream(fmt.Sprintf("%s.added", co.OutputPath), output_frmt)
	if err != nil {
		return err
	}
	out2, outPath2, err := createOutputStream(fmt.Sprintf("%s.removed", co.OutputPath), output_frmt)
	if err != nil {
		return err
	}

	dfs := diff.NewService(
		diff.WithFormat(output_frmt),
	)

	if err := dfs.Diff(ctx, f1, f2, out1, out2); err != nil {
		out1.Close()
		out2.Close()

		if !overwrited {
			return err
		}

		log.Debugf("removing output file %s", *outPath1)
		if rerr := os.Remove(*outPath1); rerr != nil {
			log.Info("failed to remove output file", zap.String("path", *outPath1), zap.Error(rerr))
		}
		log.Debugf("removing output file %s", *outPath2)
		if rerr := os.Remove(*outPath2); rerr != nil {
			log.Info("failed to remove output file", zap.String("path", *outPath2), zap.Error(rerr))
		}

		return err
	}

	return nil
}
