# Certificate Chain Validation Tool

This tool validates X.509 certificate chains by performing the following checks:

- End-entity certificate is signed by Intermediate CA
- Intermediate CA certificate is signed by Root CA
- All certificates are within their validity periods
- Intermediate CA has proper BasicConstraints (CA=True)

## Requirements

- Python 3.6+
- Dependencies:
  - pytest
  - cryptography

Install dependencies with:
```bash
pip install pytest cryptography
```

## Usage

Run the validation tool using pytest with the following command:

```bash
pytest -s --root-ca /path/to/root.pem --intermediate-ca /path/to/intermediate.pem --end-entity /path/to/end.pem

e.g pytest -s --root-ca rootCA.pem --intermediate-ca intermediateCA.pem --end-entity leaf.pem
```
* leaf is equivalent of citizen's certificate, intermediateCA is similar to Iran Digital Citizen CA, and rootCa
### Command Line Arguments

- `--root-ca`: Path to the root CA certificate file (PEM or DER format)
- `--intermediate-ca`: Path to the intermediate CA certificate file (PEM or DER format)
- `--end-entity`: Path to the end-entity/leaf certificate file (PEM or DER format)

## How It Works

The tool performs manual path validation by:
1. Loading all certificates from the specified files
2. Verifying certificate validity periods
3. Checking intermediate CA basic constraints
4. Verifying certificate signatures through the chain
5. Providing detailed output of the validation process

## Example Output

When successful, you'll see validation results for each step of the process and a final summary showing all checks passed.

## Notes

- This validation confirms the certificate chain's integrity without enforcing Extended Key Usage (EKU) constraints.
- Supports both PEM and DER formatted certificates.
