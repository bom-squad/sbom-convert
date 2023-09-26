package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/bom-squad/go-cli/cmd/cli/options"
	"github.com/bom-squad/go-cli/pkg/convert"
	"github.com/bom-squad/go-cli/pkg/format"
)

var outputDirPermissions = 0o755

func ConvertCommand() *cobra.Command {
	co := &options.ConvertOptions{}
	c := &cobra.Command{
		Use:        "convert",
		Aliases:    []string{"cv"},
		SuggestFor: []string{"convert"},
		Short:      "Convert between CycloneDX and SPDX SBOMs",
		Long:       `Convert between CycloneDX and SPDX, or vice versa, including different specification versions.`,
		Example: `
sbom-convert convert sbom.cdx.json         			output to stdout in inverse format
sbom-convert convert sbom.spdx.json -o sbom.cdx.json            output to a file
sbom-convert convert sbom.cdx.json -f spdx-2.3         		select to a specific format
sbom-convert convert sbom.cdx.json -f spdx -e text   	        select specific encoding
	 				`,
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		Args:              cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConvert(cmd.Context(), co, args)
		},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := cmd.Parent().PersistentPreRunE(cmd.Parent(), args); err != nil {
				return err
			}

			if err := options.BindConfig(viper.GetViper(), cmd); err != nil {
				return err
			}

			return validateConvertOptions(co, args)
		},
	}

	co.AddFlags(c)

	return c
}

func validateConvertOptions(co *options.ConvertOptions, args []string) error {
	return nil
}

// runConvert is the main entrypoint for the `convert` command
func runConvert(ctx context.Context, co *options.ConvertOptions, args []string) error {
	log := zap.S()
	f, err := os.Open(args[0])
	if err != nil {
		return err
	}

	defer f.Close()

	frmt, err := parseFormat(co.Format, co.Encoding, f)
	if err != nil {
		return err
	}

	overwrited := false
	_, err = os.Stat(co.OutputPath)
	if err != nil {
		log.Debug("output path already exists, overwriting")
		overwrited = true
	}

	out, path, err := createOutputStream(co.OutputPath, frmt)
	if err != nil {
		return err
	}

	cs := convert.NewService(
		convert.WithFormat(frmt),
		convert.WithSelectRoot(co.SelectRoot),
		convert.WithVirtualRootScheme(co.VirtRootScheme),
	)

	if err := cs.Convert(ctx, f, out); err != nil {
		out.Close()

		if !overwrited {
			return err
		}

		log.Debugf("removing output file %s", *path)
		if rerr := os.Remove(*path); rerr != nil {
			log.Info("failed to remove output file", zap.String("path", *path), zap.Error(rerr))
		}

		return err
	}

	return nil
}

// parseFormat parses the format string and returns target format
// if format string is empty, it will try to detect the format automatically and return the inverse
func parseFormat(f, e string, r io.ReadSeekCloser) (*format.Format, error) {
	if f == "" {
		df, err := format.DetectFormat(r)
		if err != nil {
			return nil, err
		}

		return df.Inverse()
	}

	format, err := format.ParseFormat(f, e)
	if err != nil {
		return nil, err
	}

	return format, nil
}

func createOutputStream(out string, frmt *format.Format) (io.WriteCloser, *string, error) {
	log := zap.S()

	if out == "" {
		log.Debug("no output path specified, using stdout")
		return os.Stdout, &out, nil
	}

	output, dir := getOutputInfo(out, frmt.Type(), frmt.Encoding())
	log.Debugf("creating output directory: %s", dir)
	if err := os.MkdirAll(dir, os.FileMode(outputDirPermissions)); err != nil {
		return nil, nil, err
	}

	o, err := os.Create(filepath.Join(dir, output))
	log.Debugf("creating output file: %s", output)
	if err != nil {
		return nil, nil, err
	}

	return o, &output, nil
}

func getOutputInfo(path, frmt, encoding string) (output, dir string) {
	// NOTE: @mrsufgi: we are autofixing the output file name to match the format
	// this is very opinionated and might not be the best UX (-o ori.file -> ori.file.cdx.json)
	// but it's the simplest way to make sure outputs are always in the right format
	dir = filepath.Dir(path)
	ext := filepath.Ext(path)
	name := strings.TrimSuffix(filepath.Base(path), ext)

	if ext != fmt.Sprintf(".%s", encoding) {
		zap.L().Debug("output path extension does not match format encoding, appending")
		name = fmt.Sprintf("%s%s", name, ext)
		ext = ""
	}
	if frmt == format.CDX {
		if strings.HasSuffix(name, ".cdx") {
			output = name
		} else {
			output = fmt.Sprintf("%s.cdx", name)
		}
	}

	if frmt == format.SPDX {
		if strings.HasSuffix(name, ".spdx") {
			output = name
		} else {
			output = fmt.Sprintf("%s.spdx", name)
		}
	}

	if ext == "" {
		if encoding == format.JSONEncoding {
			zap.L().Debug("output path does not contain a valid format extension, appending")
			output = fmt.Sprintf("%s.%s", output, encoding)
		}
	} else {
		output = fmt.Sprintf("%s%s", output, ext)
	}

	return output, dir
}
