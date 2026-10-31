# Real-log demo sample

`firex-500mib.log` is a 524,288,146-byte, complete-line prefix of the user-supplied
`firex-10G.log`, containing 992,884 records. It is tracked using Git LFS.

After cloning, run `git lfs install` and `git lfs pull`. Verify the SHA-256 against
`firex-500mib.log.manifest.json`. The original source remains unchanged. Recreate
the extraction using `python scripts/sample_log.py --input PATH --output NEW_PATH
--mib 500`; the script refuses to overwrite an existing output.

This sample preserves original network identifiers. A credential-field-name scan
found no matches; that scan is not a guarantee of anonymity or a complete secret
audit. Do not describe this as anonymized data or independently validated attacks.

The input covers only a contiguous prefix. Real-log pipeline execution and
self-supervised link ranking do not establish detection precision/recall. Use the
separate, clearly labeled planted-chain test for known-ground-truth demonstrations.
