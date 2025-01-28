# CVE Search

This Python tool searches for Common Vulnerabilities and Exposures (CVEs) affecting a specified program and version within a local CVE database.

## Features

- **Fast JSON Processing**: Utilizes `orjson` for efficient JSON parsing.
- **Parallel Processing**: Employs multiprocessing to scan files concurrently, significantly reducing search time.
- **Semantic Versioning**: Supports complex version range comparisons to accurately determine affected versions.
- **Interactive Input**: Prompts the user for necessary inputs, making the tool user-friendly.
- **CVE Source Integration**: Currently integrated with CVEs from 2024 and 2025 sourced from the CVE Project.

## Prerequisites

- **Python 3.9** or later

## Installation

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/kw-soft/cvesearch.git
    cd cvesearch
    ```

2. **Create a Virtual Environment** (optional but recommended):
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3. **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. **Prepare Your CVE Database**:
    - Ensure you have a directory containing all your CVE JSON files. For example: `./`.
    - Currently, only CVEs from **2024** and **2025** are integrated. These should be placed directly in the base path (`./`).

2. **Run the Script**:
    ```bash
    python main.py
    ```

3. **Provide the Required Inputs**:
    
    - **Program Name**: Enter the exact name of the program you want to search for (e.g., `git`).
    - **Program Version**: Enter the specific version of the program you want to check (e.g., `2.31.1`).

4. **View the Results**:
    - The script will display a progress indicator.
    - Upon completion, it will list all found CVEs along with their CVSS scores.

### Example

```bash

Program name: git
Program version: 2.31.1
```
### Output

```bash

Files to process: 66128
Progress: 100/66128 files processed

Found CVEs:
CVE-2023-22490 cvss: 5.5
CVE-2023-22743 cvss: 7.3

Total 17 CVEs found.

```


## Integrating Additional CVEs

The current CVE database includes CVEs from **2024** and **2025**, sourced from the [CVE Project's cvelistV5](https://github.com/CVEProject/cvelistV5). To integrate additional CVEs from other years or sources, follow these steps:

### 1. Download Additional CVEs

- **From CVE Project's cvelistV5**:
  - Visit the [CVE Project's cvelistV5 repository](https://github.com/CVEProject/cvelistV5) to download CVE JSON files.

- **From Other Trusted Sources**:
  - Alternatively, obtain CVE data from other trusted sources in JSON format.

### 2. Add CVE Files to the Database

- **Copy Files**:
  - Copy the downloaded CVE JSON files directly into the base path directory (`./`).

- **Ensure Consistency**:
  - Ensure that all CVE files are in JSON format and follow the same structure as the existing files.



### Project Structure

```bash
cvesearch/
├── main.py        # Main script with the search functionality
├── requirements.txt     # Python dependencies
├── README.md            # Project description
├── .gitignore           # Files and directories to ignore in Git
```

### Contributing

Contributions are welcome! Please fork the repository and create a pull request with your changes.

### License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

### Acknowledgements

- [orjson](https://github.com/ijl/orjson) for fast JSON parsing.
- [packaging](https://packaging.pypa.io/) for version comparison utilities.
- [CVE Project](https://github.com/CVEProject/cvelistV5) for providing comprehensive CVE lists.

