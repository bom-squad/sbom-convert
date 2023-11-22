package convert

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	max_test_count     int
	test_spdx_json     bool
	test_spdx_keyvalue bool
	test_cdx_json      bool
)

func init() {
	flag.IntVar(&max_test_count, "max_test_count", 100, "Maximum number of test files")
	flag.BoolVar(&test_spdx_json, "test_spdx_json", true, "Test SPDX json files")
	flag.BoolVar(&test_spdx_keyvalue, "test_spdx_keyvalue", false, "Test SPDX key-value files")
	flag.BoolVar(&test_cdx_json, "test_cdx_json", true, "Test CycloneDX json files")
}

func ExtractLicenses(input string) []string {
	input = strings.NewReplacer("(", "", ")", "").Replace(input)
	licenses := regexp.MustCompile(`\s*(OR|AND)\s*`).Split(input, -1)
	var result []string
	for _, license := range licenses {
		if license != "" {
			result = append(result, license)
		}
	}
	return result
}

func FilterLicenses(licenses []string) []string {
	var result []string
	for _, license := range licenses {
		switch license {
		case "", "None", "NONE", "NOASSERTION":
			continue
		default:
			result = append(result, license)
		}
	}
	return result
}

func GetPurlsCount(json_str string) int {
	var data map[string]interface{}
	err := json.Unmarshal([]byte(json_str), &data)
	if err != nil {
		fmt.Println("Error:", err)
	}

	purls := []string{}

	if _, exists := data["spdxVersion"]; exists {
		packages := data["packages"].([]interface{})
		for _, pkg := range packages {
			packageMap := pkg.(map[string]interface{})
			if externalRefs, ok := packageMap["externalRefs"].([]interface{}); ok {
				for _, ref := range externalRefs {
					refMap := ref.(map[string]interface{})
					if refType, ok := refMap["referenceType"].(string); ok && refType == "purl" {
						if refLocator, ok := refMap["referenceLocator"].(string); ok {
							purls = append(purls, refLocator)
						}
					}
				}
			}
		}
	} else {
		components := data["components"].([]interface{})
		for _, component := range components {
			componentMap := component.(map[string]interface{})
			if purl, ok := componentMap["purl"].(string); ok {
				purls = append(purls, purl)
			}

			if subcomponents, ok := componentMap["components"].([]interface{}); ok {
				for _, subcomponent := range subcomponents {
					subcomponentMap := subcomponent.(map[string]interface{})
					if purl, ok := subcomponentMap["purl"].(string); ok {
						purls = append(purls, purl)
					}
				}
			}
		}
	}
	return len(purls)
}

func GetLicensesCount(json_str string) int {
	var data map[string]interface{}
	err := json.Unmarshal([]byte(json_str), &data)
	if err != nil {
		fmt.Println("Error:", err)
	}

	licenses := map[string]struct{}{}

	if _, exists := data["spdxVersion"]; exists {
		packages, _ := data["packages"].([]interface{})
		for _, pkg := range packages {
			packageMap, _ := pkg.(map[string]interface{})

			if licenseConcluded, ok := packageMap["licenseConcluded"].(string); ok {
				concludedLicenses := ExtractLicenses(licenseConcluded)
				for _, lic := range FilterLicenses(concludedLicenses) {
					licenses[lic] = struct{}{}
				}
			}

			// if licenseDeclared, ok := packageMap["licenseDeclared"].(string); ok {
			// 	declaredLicenses := ExtractLicenses(licenseDeclared)
			// 	for _, lic := range FilterLicenses(declaredLicenses) {
			// 		licenses[lic] = struct{}{}
			// 	}
			// }
		}
	} else {
		components, _ := data["components"].([]interface{})
		for _, component := range components {
			componentMap, _ := component.(map[string]interface{})
			if licensesList, ok := componentMap["licenses"].([]interface{}); ok {
				for _, license := range licensesList {
					if licenseMap, ok := license.(map[string]interface{}); ok {
						if licenseIDMap, ok := licenseMap["license"].(map[string]interface{}); ok {
							if licenseID, ok := licenseIDMap["id"].(string); ok {
								licenses[licenseID] = struct{}{}
							}
						}
					}
				}
			}
		}
	}
	return len(licenses)
}

func DownloadSBOMs() {
	fileURL := "https://drive.usercontent.google.com/download?id=1LgGlq3g_H02mhzkc94cUd0zzxy0JhFim&export=download&authuser=0&confirm=t&uuid=483eac07-f1af-4356-abeb-4ba254e32b86&at=APZUnTWjSNLUgCQ8wwFZjsLS7Y36:1694113089657"
	tarPath := "./SBOM.tar.xz"

	resp, err := http.Get(fileURL)
	if err != nil {
		log.Fatalf("Error making GET request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Error: HTTP status code %d", resp.StatusCode)
	}

	outputFile, err := os.Create(tarPath)
	if err != nil {
		log.Fatalf("Error creating output file: %v", err)
	}
	defer outputFile.Close()

	_, err = io.Copy(outputFile, resp.Body)
	if err != nil {
		log.Fatalf("Error copying content to output file: %v", err)
	}

	fmt.Println("SBOMs downloaded successfully.")

	cmd := exec.Command("tar", "-xJf", tarPath)
	cmd.Dir = "./"

	err = cmd.Run()
	if err != nil {
		log.Fatalf("Error extracting file: %v", err)
	}

	fmt.Println("SBOMs extracted successfully.")
}

func readJSONFile(path string, prefix string) (string, error) {
	var result string
	files, err := filepath.Glob(path + prefix + ".*.json")
	if err != nil {
		return "", err
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		result = string(data)
	}
	return result, nil
}

func TestCount(t *testing.T) {
	sbomFolder := "./SBOM/"
	_, err := os.Stat(sbomFolder)

	if os.IsNotExist(err) {
		// sbomFolder does not exist, download it.
		fmt.Println("Downloading SBOMs from Google Drive...")
		DownloadSBOMs()
	} else if err != nil {
		fmt.Printf("Error checking SBOM folder: %v\n", err)
		return
	}

	SBOM_CONVERT_PATH := "../../dist/sbom-convert_linux_amd64_v1/sbom-convert"

	SBOM_CONVERT_ABSPATH, _ := filepath.Abs(SBOM_CONVERT_PATH)
	_, err2 := os.Stat(SBOM_CONVERT_ABSPATH)
	if os.IsNotExist(err2) {
		fmt.Printf("Binary does not exist: %s.\nRun make binary first!\nExiting...\n", SBOM_CONVERT_ABSPATH)
		return
	}

	fileInfos, err := os.ReadDir(sbomFolder)
	if err != nil {
		fmt.Println("Error reading directory:", err)
		return
	}
	tested_count := 0
	for _, fileInfo := range fileInfos {
		filename := fileInfo.Name()

		if test_spdx_json == false && strings.Contains(filename, "_spdx.json") {
			continue
		}

		if test_spdx_keyvalue == false && strings.Contains(filename, "_spdx.txt") {
			continue
		}

		if test_cdx_json == false && strings.Contains(filename, "_cyclonedx.json") {
			continue
		}

		filePath := filepath.Join(sbomFolder, filename)

		tested_count++
		if tested_count > max_test_count {
			fmt.Printf("Reached max_test_count: %d\n", max_test_count)
			break
		}
		fmt.Printf("=> (%d/%d) Testing %s\n", tested_count, max_test_count, filePath)

		data, err := os.ReadFile(filePath)
		ori_json := string(data)
		if err != nil {
			fmt.Println("Error reading file:", err, "Skipping...")
			continue
		}

		prefix := filename[:len(filename)-len(filepath.Ext(filename))]

		cmd := exec.Command(SBOM_CONVERT_ABSPATH, filePath, "-o", prefix)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("Convert Check failed: %s\n %s", err, string(output))
			continue
		}
		fmt.Printf("convert successfully\n")

		converted_json, err := readJSONFile("./", prefix)
		// fmt.Println(converted_json)

		ori_purls_count := GetPurlsCount(ori_json)
		fmt.Printf("ori_purls_count: %d\n", ori_purls_count)

		converted_purls_count := GetPurlsCount(converted_json)
		fmt.Printf("converted_purls_count: %d\n", converted_purls_count)
		// continue

		if ori_purls_count > 0 && ori_purls_count > converted_purls_count {
			t.Errorf("PURL Check failed. 'Original PURL Count:', %d, 'Converted PURL Count:' %d", ori_purls_count, converted_purls_count)
		}

		ori_licenses_count := GetLicensesCount(ori_json)
		fmt.Printf("ori_licenses_count: %d\n", ori_licenses_count)
		converted_licenses_count := GetLicensesCount(converted_json)
		fmt.Printf("converted_licenses_count: %d\n", converted_licenses_count)

		if ori_licenses_count > 0 && ori_licenses_count != converted_licenses_count {
			t.Errorf("License Check failed. 'Original License Count:', %d, 'Converted License Count:' %d", ori_licenses_count, converted_licenses_count)
		}

		files, err := filepath.Glob(prefix + "*.json")
		if err != nil {
			panic(err)
		}
		for _, file := range files {
			err := os.Remove(file)
			if err != nil {
				panic(err)
			}
			fmt.Printf("Removed file: %s\n", file)
		}
	}

	// delete downloaded SBOM files and the SBOM.tar.xz file
	os.RemoveAll(sbomFolder)
	os.Remove("SBOM.tar.xz")
}
