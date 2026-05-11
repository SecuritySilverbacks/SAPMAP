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

# Verify it's running
cf apps | grep sapmap-probe-bridge
# expected: sapmap-probe-bridge   started   1/1   64M   64M   sapmap-probe-bridge-…
```

`cf push` will read `manifest.yml` + `Staticfile` from the current
directory and use the `staticfile_buildpack`.  Total time ~60s.

## Open the tunnel

```bash
# Replace <region> with your actual region (eu10, us10, ap10, …)
cf ssh -L 20003:connectivityproxy.internal.cf.<region>.hana.ondemand.com:20003 \
       sapmap-probe-bridge
```

Leave that terminal open.  `localhost:20003` is now a TCP forward into
BTP's connectivity proxy.  Sanity-check with `nc -zv localhost 20003` —
should report "succeeded".

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
| `cf push` fails with "no available cells" | Subaccount is out of memory quota — free some up or shrink another app |
| `cf ssh` says "SSH support is disabled for app" | Run `cf enable-ssh sapmap-probe-bridge && cf restart sapmap-probe-bridge` |
| Tunnel opens but probe still times out | Wrong region in the `cf ssh -L` target — check `cf api` matches the SCC's region |
| `cf ssh` says "SSH is disabled for the space" | Org/Space SSH policy blocks it — ask an org manager to `cf allow-space-ssh <space>` |
| Probe runs but returns 401 | PP cert was minted but the on-prem USREXTID rule didn't resolve to a real ABAP user — re-check the PP analyser verdict |

## Cost

64 MB of memory in your subaccount for the duration of the engagement.
At BTP CF rates (varies by tier) this is a few cents per day.  Stop the
app between sessions to avoid even that.
