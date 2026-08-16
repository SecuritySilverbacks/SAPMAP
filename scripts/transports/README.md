# Bundled transport exploits

These are pre-built ABAP transport requests SAPMAP can inject into a
victim ABAP system via `sap_transport_import.py` (the "Import Local
Transport (zip)" ctx-menu action on any ABAP node in the GUI).

The injection pipeline is **SID-agnostic**: it reads the source SID out
of the CO header (`K<num>.<SID>`) and hands the whole `SIDK<num>`
trkorr to `tp addtobuffer` + `tp import` on the target with the
cross-domain unconditional flags. There is no requirement that the
target system share a transport domain with the source, nor that the
source SID even exist in the victim landscape.

## Contents

| Zip                                    | Report          | Trkorr        | What it does |
|----------------------------------------|-----------------|---------------|--------------|
| `ZSAPMAP_CANARY_S4H_900070.zip`        | ZSAPMAP_CANARY  | `S4HK900070`  | Writes a `SAPMAP canary import verified at <ts>` line to SM21 via `RSLG_WRITE_SYSLOG_ENTRY`. Harmless smoke test — proves the whole `tp addtobuffer` + `tp import` chain landed AND the after-import execution fired. |
| `ZSAPMAP_USRCREATE_S4H_900072.zip`     | ZSAPMAP_USRCREATE | `S4HK900072` | Calls `BAPI_USER_CREATE1` for `SAPMAP00` (service user, password `Andinyougo123!`), then `BAPI_USER_PROFILES_ASSIGN` with `SAP_ALL`, then `BAPI_TRANSACTION_COMMIT`. Instant SAP_ALL landfall on any client the operator picks at import time. |

Raw `K` (cofile) + `R` (datafile) pairs are kept alongside the zips for
inspection and re-zipping. The pipeline only needs the zips.

### XPRA (Execute After Import) — required

Both transports carry an **R3TR XPRA** entry alongside the R3TR PROG
object. XPRA tells `tp` to auto-execute the report as a post-import
step; without it the transport merely installs the source into REPOSRC
and sits idle — the operator would then need SE38 access on the target
to actually run it, which defeats the point.

The CO header field at position 10 (the count column) is `2` on both
transports here, versus `1` for a plain PROG-only transport. If you
rebuild your own transports and see count=1, you forgot to add the
`XPRA` line in SE01 → Object List Editor.

## Source

Released from the SAPMAP author's dev sandbox (`S4H` @ 192.168.2.209) on
2026-08-16. See ABAP source for both reports in the task history / commit
message body. Both requests are of type `A G - C R 7 T - Z` (customer
workbench, released) so `tp` will accept them without a developer key on
the target.

## Adding new bundled transports

1. Write the ABAP report on any dev system where you hold a dev key.
2. Release the request in SE01 (workbench request, `Z*` object range).
3. Copy the `K<num>.<SID>` and `R<num>.<SID>` pair out of
   `/usr/sap/trans/{cofiles,data}/`.
4. `zip -j <descriptive-name>.zip K<num>.<SID> R<num>.<SID>`.
5. Drop the zip in this directory and add a row to the table above.

## Runtime flow

```
operator picks node -> ctx menu "Import Local Transport (zip)"
    -> uploads zip
    -> POST /api/node/<sid>/import_transport
    -> parse_transport_zip()  (validates K+R pair, same num+SID)
    -> _resolve_channel()      (gw SAPXPG if vulnerable, else SXPG_STEP_XPG_START)
    -> _discover_trans_dir()   (probes /usr/sap/trans + TP profile path)
    -> _upload_binary()         (chunked base64 write of K, then R)
    -> _run_tp("addtobuffer S4HK900066 <TARGET_SID> pf=...")
    -> _run_tp("import      S4HK900066 <TARGET_SID> client<CCC> U1268")
    -> GUI polls /transport_progress until phase="done"
```

The `U1268` unconditional-mode flags let `tp` import across transport
domains, ignore missing source-system records, ignore target release
mismatches, and skip the invalid-target-version check. That combination
is what makes a foreign-SID transport importable on a system that has
never heard of the source system.
