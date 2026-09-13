# One Bridge

One Bridge is a Home Assistant custom integration for a typed, allowlisted GPT Action bridge.

## Status

The public `0.x` series is a preview line. It is intended for real testing, but configuration, UI and API details may still change before `1.0.0`.

## One Bridge vs. the private Developer Bridge

One Bridge is the **public Home Assistant product**. It is installed through HACS, normally runs with the `target` role and exposes only capabilities allowed by Home Assistant.

The private Legacy / Developer Bridge is a separate `source`-role development tool used for release, Git and bootstrap work. Public One Bridge does **not** expose private source Git, worker release or arbitrary shell access.

## Access presets

One Bridge has five server-enforced access presets:

| Preset | What it allows |
|---|---|
| **Minimal read access** | Basic status and Home Assistant read operations; no mutation/apply |
| **Home control (recommended)** | `status:read`, `control:read`, `control:write` and `mutation:apply` |
| **All read-only areas** | All available `*:read` capabilities for the target role; no writes/apply |
| **Advanced – all role capabilities** | Every capability allowed to the current role; still no source-only Git/release capabilities on `target` |
| **Custom** | Explicit capability selection, validated server-side |

For Custom, `status:read` is always retained. If any write capability is selected, `mutation:apply` is added automatically.

## Read-only lockdown

Read-only lockdown is a separate server-side safety switch on top of the preset. When enabled, `prepare` and `apply` operations are filtered out even if the selected preset normally includes write capabilities.

Example: **Advanced + read-only lockdown** exposes the readable part of Advanced, but no mutations.

## Operation modes

Modes describe the safety flow, not the permission preset:

| Mode | Meaning | Changes Home Assistant? |
|---|---|---|
| `read` | Read status/data | No |
| `prepare` | Validate and bind one exact mutation to a `prepare_id` and digest | No |
| `apply` | Execute exactly the previously prepared mutation | Yes |

Mutations therefore follow `read → prepare → review → apply → verify`.

If an apply response is lost, do **not** retry blindly. Recovery V2 provides read-only `system.prepare.status` and `system.apply.status` lookups so the server-side outcome can be recovered safely.

## Installation roles

The public HACS build is **target-only**. `target` is the only accepted public role and is recommended for all One Bridge installations.

The `source` role exists only in the private Legacy / Developer Bridge. Public One Bridge removes that role at build time, so source-only capabilities such as `git:commit`, bootstrap maintenance and `deployment:source` cannot be enabled through public configuration.

## Internal WebSocket mode

This is transport, not permissions:

- **Auto** — One Bridge derives the internal Home Assistant WebSocket connection automatically.
- **Custom** — use an explicitly configured loopback `ws://` or `wss://.../api/websocket` endpoint.

Auto is the recommended default.

## Security model

One Bridge is read-first. Mutations use a server-generated prepare/apply flow with explicit confirmation, validation, audit metadata and post-apply verification. The integration does not expose an arbitrary shell, generic HTTP proxy or direct `.storage` writer.

## Install with HACS

1. In HACS, add this repository as a custom repository with category **Integration**.
2. Install **One Bridge**.
3. Restart Home Assistant.
4. Go to **Settings → Devices & services → Add integration** and select **One Bridge**.
5. Use the `target` role for ordinary HACS installations. The `source` role is an advanced release-source mode and requires a local release policy that is not included in this public repository.

## GPT Action setup

The Home Assistant setup flow guides the complete GPT connection:

1. Enter the public Home Assistant HTTPS origin and choose the installation role/access policy.
2. Copy the generated OAuth Client ID, one-time Client Secret, Authorization URL, Token URL and scope, then complete the Home Assistant setup.
3. Import the stable schema URL into the GPT Action. It ends in `/api/one_bridge/v1/openapi.yaml` and is generated from the capabilities currently allowed by Home Assistant.
4. Configure OAuth in the GPT editor. When the editor provides its callback URL, open One Bridge Options in Home Assistant and paste that callback there before signing in.
5. Copy the generated textual GPT instructions, or open the stable `/api/one_bridge/v1/instructions.txt` URL.

One Bridge uses the Home Assistant domain `one_bridge`, its own `/api/one_bridge/v1` HTTP namespace and separate runtime configuration. It can therefore coexist with the legacy/private integration during migration.

One Bridge options can later change the callback URL, access preset/capabilities, read-only lockdown and OAuth security settings. Client-secret rotation is available from Options and the replacement secret is shown once. If permissions change, re-import the same stable schema URL in the GPT editor so its operation list is refreshed.

## Public repository scope

This repository contains the Home Assistant integration and public validation only. Private deployment state, OAuth credentials, local release policy and historical source-repository data are intentionally excluded.

## Support

Use the GitHub issue tracker for reproducible bugs and feature requests.
