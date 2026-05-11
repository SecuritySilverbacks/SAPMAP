# BTP probe bridge — minimal CF app for `cf ssh` tunnelling

The SAPMAP PP-impersonation live probe ("Verify PP Impersonation") drives
an HTTP CONNECT through BTP's connectivity proxy at:

    connectivityproxy.internal.cf.<region>.hana.ondemand.com:20003

That hostname only resolves and accepts connections from **inside** BTP's
Cloud Foundry runtime — so from a developer workstation the TCP connect
just times out.  The standard workaround is to push a tiny app to your
subaccount and use `cf ssh -L` to tunnel through it.

This directory is exactly that tiny app — 64 MB of RAM, serves a single
static HTML page nobody will ever look at.  It exists only as an SSH
target.

## One-time setup

```bash
# Log in to the right CF API + org + space
cf login -a https://api.cf.eu10.hana.ondemand.com   # change region as needed
cf target -o "<your-org>" -s "<your-space>"

# Push the bridge app from this directory
cd tools/btp_ssh_bridge
cf push

# CF apps default to SSH-DISABLED on most BTP subaccounts.  Enable it
# on the app, then restart so the diego cell picks up the change.
# (You can verify with `cf ssh-enabled sapmap-probe-bridge`.)
cf enable-ssh sapmap-probe-bridge
cf restart    sapmap-probe-bridge

# Verify it's running with SSH ready
cf apps | grep sapmap-probe-bridge
# expected: sapmap-probe-bridge   started   1/1   64M   64M   sapmap-probe-bridge-…
```

`cf push` will read `manifest.yml` + `Staticfile` from the current
directory and use the `staticfile_buildpack`.  Total time ~60s.

> If `cf enable-ssh` reports "SSH support is disabled for the space",
> ask an org manager to run `cf allow-space-ssh <your-space>` first.
> Per-app SSH can't override a per-space disallow.

> **Why is `cf enable-ssh` a separate step?**  CF's app manifest spec
> has no `enable-ssh` key — SSH is toggled via a dedicated API call
> (`PATCH /v3/apps/<guid>/features/ssh`), so it can't be encoded in
> `manifest.yml` no matter how we'd like to.  The `cf enable-ssh`
> command is the supported way to flip that flag, and it needs a
> `cf restart` for the change to take effect on the diego cell.

## Open the tunnel

```bash
# Replace <region> with your actual region (eu10, us10, ap10, …)
cf ssh -L 20003:connectivityproxy.internal.cf.<region>.hana.ondemand.com:20003 \
       sapmap-probe-bridge
```

Leave that terminal open.  `localhost:20003` is now a TCP forward into
BTP's connectivity proxy.  Sanity-check with `nc -zv localhost 20003` —
should report "succeeded".

## Get a connectivity-service token (HTTP 407 path)

If the probe runs through the tunnel but the connectivity proxy
returns **HTTP 407 Proxy Authentication Required**, the proxy is
rejecting the user JWT as proxy auth — it wants a
**connectivity-service-bound** token instead.  Those are minted by the
Connectivity service's own UAA via the `client_credentials` grant.

You only have to do this once per engagement — the token stays valid
for an hour or two.

```bash
# 1. Discover the Connectivity service offering + plans.  In every
#    BTP CF subaccount the offering is called "connectivity"; the
#    free plan is "lite".  Verify with:
#       cf marketplace -e connectivity
#    (Lists rows like:  connectivity  lite, connectivity_proxy)

# 2. Create a connectivity service INSTANCE.  cf bind-service wants
#    an instance name, not the offering name — and instances must be
#    explicitly created per space.
cf create-service connectivity lite sapmap-connectivity
# Wait for the instance to be ready (usually instant):
cf service sapmap-connectivity      # → "status: create succeeded"

# 3. Bind the instance to the bridge app and restart so VCAP_SERVICES
#    picks up the credentials.
cf bind-service sapmap-probe-bridge sapmap-connectivity
cf restart      sapmap-probe-bridge

# 4. cf ssh into the app and mint a token
cf ssh sapmap-probe-bridge
# inside the container:
CRED=$(echo "$VCAP_SERVICES" | jq -r '.connectivity[0].credentials')
URL=$(echo  "$CRED" | jq -r .url)
CID=$(echo  "$CRED" | jq -r .clientid)
SEC=$(echo  "$CRED" | jq -r .clientsecret)
TOK=$(curl -s -X POST "$URL/oauth/token" \
        -d "grant_type=client_credentials&client_id=$CID&client_secret=$SEC" \
      | jq -r .access_token)
echo "$TOK"          # copy this; paste into SAPMAP
exit
```

In SAPMAP: **File → ☁ BTP — Connectivity Proxy Override** → paste the
token into the *Connectivity-service JWT* field → **Save**.  Re-run
the probe; the 407 should now be replaced with a real upstream HTTP
status from S4H.

> The connectivity-service token IS sensitive material — it grants
> access to call your subaccount's connectivity proxy.  SAPMAP stores
> it in process memory only and never writes it to disk.  Don't paste
> it into chat / tickets / screenshots.

## Run the probe

In SAPMAP, right-click the ABAP node → Exploitation → **🎯 Verify PP
Impersonation (Live Probe)**.

When the confirm dialog appears:

1. Click **Cancel**.
2. In the override prompt, leave the pre-filled value `localhost:20003`
   and click OK.

The probe will now route through your `cf ssh` tunnel.  Expected output:

```
[*] PP-verify S4H: reusing PP destination 'S4H_PP' (or creating temp)
[*] PP-verify S4H: probing http://192.168.2.209:8080/sap/bc/ping via localhost:20003
[+] PP-verify S4H: HTTP 200 (42 ms) — impersonation CONFIRMED as DDIC (confidence HIGH)
```

The SCC↔S4H edge on the map turns **solid red** with a `[PP CONFIRMED]`
label, and a CRITICAL finding `scc.pp.impersonation.confirmed` fires.

## Cleanup

When the engagement is over:

```bash
# Close the ssh tunnel terminal (Ctrl-C / exit)
cf stop sapmap-probe-bridge
cf delete sapmap-probe-bridge -f -r    # -r also removes the route
```

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `cf push` returns HTTP 500 / `UnknownError` | Older versions of this manifest used `${random-word}.${domain}` route templates which not every CF API can resolve.  Pull the latest `manifest.yml` (uses `random-route: true` instead) and retry. |
| `cf push` fails with "no available cells" | Subaccount is out of memory quota — free some up or shrink another app |
| `cf ssh` says "SSH support is disabled for app" | Run `cf enable-ssh sapmap-probe-bridge && cf restart sapmap-probe-bridge` (this is the default on most BTP subaccounts — the one-time setup above already covers it) |
| Tunnel opens but probe still times out | Wrong region in the `cf ssh -L` target — check `cf api` matches the SCC's region |
| `cf ssh` says "SSH is disabled for the space" | Org/Space SSH policy blocks it — ask an org manager to `cf allow-space-ssh <space>` |
| Probe runs but returns 401 | PP cert was minted but the on-prem USREXTID rule didn't resolve to a real ABAP user — re-check the PP analyser verdict |
| `cf bind-service` says "Service instance 'connectivity' not found" | You need to CREATE the instance first — `cf bind-service` expects an instance name, not the service offering name.  Run `cf create-service connectivity lite sapmap-connectivity`, then bind that instance. |
| `cf create-service connectivity lite` fails with "service not found" | The subaccount may not have the Connectivity service entitled to this space.  Ask an org manager / global account admin to entitle "connectivity, lite" via BTP Cockpit → Entity Configuration → Entitlements. |

## Cost

64 MB of memory in your subaccount for the duration of the engagement.
At BTP CF rates (varies by tier) this is a few cents per day.  Stop the
app between sessions to avoid even that.
