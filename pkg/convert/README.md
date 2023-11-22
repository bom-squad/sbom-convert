# Unit and Fuzz Testing for SBOM Conversion

This repository contains a Go unit test file aimed at evaluating the accuracy and integrity of the Software Bill of Materials (SBOM) conversion process. It ensures that the SBOM conversion maintains specific properties and is error-free.

## How it Functions

This unit test file operates through the following steps to validate SBOM conversion:

1. **Unit Test**: 
    - Automatically Download our shared [SBOM dataset](https://drive.google.com/file/d/1LgGlq3g_H02mhzkc94cUd0zzxy0JhFim/view?usp=sharing), comprising 10,494 SBOM files in both SPDX and CycloneDX formats.
   - Utilize the sbom-convert tool for converting SBOMs from one format to another.
   - Verify that the sbom-convert tool does not encounter any errors.
   - Compare the counts of PURLs in the original and converted SBOMs.
   - Compare the counts of licenses in the original and converted SBOMs.

2. **Fuzzing Test**:
    - The fuzzer takes seed inputs and generates new inputs through mutations.
    - It then checks if the binary fails when exposed to certain corner cases.

## Getting Started

### Running the Unit Test

1. **Run the Unit Test**: Execute the following command in your project's root directory:

   ```bash
   make unittest
   ```

2. **Run the Fuzzing Test**: Execute the following command in your project's root directory:

   ```bash
   make fuzztest
   ```

## Contribution

The current unit tests primarily focus on conversion, PURL counts, and license counts. Additional unit tests will be added in the future. If you have suggestions, improvements, or bug fixes, please don't hesitate to reach out and contribute to the project. Your input is highly valued.