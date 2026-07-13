# sap_decompress

A small ELF binary that decompresses SAP's proprietary LZH format —
the compression scheme used inside `GET_TABLEBLOCK_COMPRESSED_RFC`
response payloads on modern S/4 kernels.  Some RFC-side table reads
(notably `RFCDES` via the compressed path) return their `BOX4096`
rows in this format; SAPMAP shells out to this binary to decompress
before parsing.

Called from `modules/discovery/sapmap_rfc.py` — a single reference,
absolute path `<repo>/tools/sap_decompress/sap_decompress`.

## Provenance

Built from the MaxDB / pysap GPL decompression library — the same
public code the [pysap](https://github.com/OpenCyberTranslated/pysap)
project ships in `pysapcompress/`.  The binary here is a static
build of that C helper compiled for `x86-64 Linux`.

## Rebuild from source

If a target architecture other than x86-64 Linux is needed (arm64,
macOS, Windows), rebuild from pysap's source and drop the resulting
binary in this folder with the same name.  No SAPMAP code change
required — the loader in `sapmap_rfc.py` just checks `os.path.isfile`
on the fixed path.

```bash
git clone https://github.com/OpenCyberTranslated/pysap
cd pysap/pysapcompress
# follow the README there — output is a `sap_decompress` static binary
cp sap_decompress <repo>/tools/sap_decompress/sap_decompress
chmod +x <repo>/tools/sap_decompress/sap_decompress
```

## Fallback behaviour

When the binary is missing (wrong architecture, permissions problem,
etc.), SAPMAP logs `sap_decompress binary not found ... skipping` and
falls through to `RFC_READ_TABLE` — slower and subject to the 512-byte
work-area limit on RFCDES, but always available.
