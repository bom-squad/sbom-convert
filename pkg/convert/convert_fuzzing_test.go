package convert

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bom-squad/protobom/pkg/reader"
)

var (
	seed_input string
)

func init() {
	flag.StringVar(&seed_input, "seed_input", "fuzz_seed_spdx.json", "Seed input file path")
}

type ReadWriteSeeker struct {
	*os.File
}

func (rws *ReadWriteSeeker) Close() error {
	return rws.File.Close()
}

func WriteStringToTempFile(content string) (io.ReadSeekCloser, error) {
	// Create a temporary file
	tempFile, err := os.CreateTemp("", "tempfile")
	if err != nil {
		return nil, err
	}

	// Write the content to the temporary file
	_, err = tempFile.WriteString(content)
	if err != nil {
		return nil, err
	}

	// Close the file to make sure all data is flushed to disk
	err = tempFile.Close()
	if err != nil {
		return nil, err
	}

	// Reopen the temporary file for reading and seeking
	file, err := os.OpenFile(tempFile.Name(), os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}

	return &ReadWriteSeeker{file}, nil
}

func ParseStreamWrapper(content string) {
	t := io.NopCloser(strings.NewReader(content))
	r := reader.New()
	t, _ = WriteStringToTempFile(content)
	t2 := t.(io.ReadSeekCloser)
	r.ParseStream(t2)
}

func FuzzParseStream(f *testing.F) {
	absPath, _ := filepath.Abs(seed_input)
	fmt.Println(absPath)
	content, err := os.ReadFile(absPath)
	if err != nil {
		log.Fatal(err)
	}
	f.Add(string(content))

	f.Fuzz(func(t *testing.T, orig string) {
		ParseStreamWrapper(orig)
	})
}