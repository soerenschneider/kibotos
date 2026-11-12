# kibotos

*κιβωτός* (Greek): a chest or ark, where valuables were kept.

Minimal Vault/OpenBao KV backup and restore. Go stdlib only. Logs in with AppRole, walks the configured paths recursively (KV v1 and v2 are detected automatically), and writes every secret as plain JSON to stdout. Restic handles encryption.

```sh
make build
cp config.example.json config.json   # edit it
restic backup --stdin-filename kibotos.json --stdin-from-command -- ./kibotos -config config.json
```

Use `--stdin-from-command` (restic 0.17+), not a pipe. With `kibotos | restic backup --stdin`, restic still creates an (empty) snapshot when kibotos fails, and `restic forget --keep-last N` can then rotate out good snapshots. With `--stdin-from-command`, restic creates no snapshot when kibotos exits non-zero.

`role_id` and `secret_id` can be left out of the config and set through `VAULT_ROLE_ID` and `VAULT_SECRET_ID` instead. The secret ID can also be read from a file with `secret_id_file` in the config or `VAULT_SECRET_ID_FILE` in the environment; surrounding whitespace, such as a trailing newline, is ignored. Environment variables take precedence over the config, and setting both a value and a file in the same place is an error. Unknown config fields are rejected.

With systemd, the secret ID can come from an encrypted credential:

```ini
[Service]
LoadCredentialEncrypted=secret-id:/etc/kibotos/secret-id.cred
Environment=VAULT_SECRET_ID_FILE=%d/secret-id
```

## Behaviour

- **Fails closed.** Any error (403, bad mount, Vault unreachable) exits non-zero and writes nothing to stdout.
- **Retries.** Network errors and HTTP 412, 429, 500, 502, 503 and 504 are retried up to 4 attempts in total, waiting 1s, 2s and 4s in between.
- **Token renewal.** The AppRole token is renewed once half its TTL has passed, so a backup can run longer than `token_ttl`. It cannot run longer than `token_max_ttl`.
- **Cleanup.** The token is revoked on exit, including on SIGINT/SIGTERM.

Output is a flat map from full secret path to its data and, for KV v2, its per-secret settings:

```json
{
  "secret/app/db": {
    "data": { "pass": "s3cr3t", "user": "admin" },
    "metadata": {
      "max_versions": 5,
      "cas_required": true,
      "delete_version_after": "1h0m0s",
      "custom_metadata": { "owner": "team-a" }
    }
  },
  "kv1/team-a/one": {
    "data": { "k": "v" }
  }
}
```

For v2 only the current version is exported, without older versions, version numbers or timestamps. Soft-deleted secrets are skipped.

A configured path such as `secret/app` covers both the secret `secret/app` and everything under `secret/app/`, since Vault allows a name to be both. If the token may not read the secret itself, it is skipped. End the path with a slash (`secret/app/`) to back up the directory only.

## Restore

```sh
restic dump latest /kibotos.json | ./kibotos -config config.json -restore -
./kibotos -config config.json -restore backup.json
```

Every secret in the file is written to its path, overwriting what is there (on v2 as a new version). A v2 secret whose current data and settings already match the file is left alone, so restoring the same file twice adds no versions. On v2 the data is written with check-and-set against the secret's current version, so it works whether or not `cas_required` is set, and the restore fails instead of overwriting a change made by someone else at the same moment. If a write is retried after its response was lost and Vault reports the check-and-set mismatch, the restore reads the secret back and carries on if it already holds the data. The metadata is written after the data, replacing any existing `custom_metadata`; if the data write fails, the secret is left untouched. Metadata is ignored when restoring into a v1 mount. `paths` in the config is ignored. Mounts must already exist, and secrets that are not in the file are left alone. To restore into another mount, rename the keys first:

```sh
jq 'with_entries(.key |= sub("^secret/"; "secret-restored/"))' backup.json | ./kibotos -config config.json -restore -
```

Note that KV v2 itself rounds integers above 2^53; KV v1 keeps them exact.

## Container image

Each release is also published as a multi-arch image (`linux/amd64`, `linux/arm64`) to `ghcr.io/soerenschneider/kibotos`, tagged with the version (`0.1.0`, `0.1`) and `latest`. It contains only the release binary on [distroless](https://github.com/GoogleContainerTools/distroless) and runs as uid 65532, so a mounted config must be readable by that user. By default it reads `/config.json`:

```sh
docker run --rm -v "$PWD/config.json:/config.json:ro" ghcr.io/soerenschneider/kibotos > backup.json
```

The image is signed keyless with cosign by the release workflow, and has an SBOM and build provenance attached:

```sh
cosign verify ghcr.io/soerenschneider/kibotos:latest \
  --certificate-identity "https://github.com/soerenschneider/kibotos/.github/workflows/release-please.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

## Required policy

Backup (KV v2 mount `secret`):

```hcl
path "secret/metadata"   { capabilities = ["list"] }
path "secret/metadata/*" { capabilities = ["read", "list"] }
path "secret/data/*"     { capabilities = ["read"] }
```

Restore additionally needs `create` and `update` on `secret/data/*` and `secret/metadata/*`. For KV v1 the paths have no `metadata/` or `data/` segment.

Example AppRole for backups. Set `token_max_ttl` above the longest expected run:

```sh
vault write auth/approle/role/kibotos token_policies=kibotos token_ttl=5m token_max_ttl=1h
```

## Tests

```sh
make tests                                                  # unit tests (fake Vault via httptest)
make integration-tests                                      # integration tests (needs Docker)
make integration-tests VAULT_IMAGE=openbao/openbao:2.7.2
make lint                                                   # golangci-lint, same as CI
```

CI runs lint, unit tests with the race detector, govulncheck, a cross-build, and the integration tests against the latest Vault and OpenBao images.

## Releases

Releases are made by [release-please](https://github.com/googleapis/release-please) from [Conventional Commits](https://www.conventionalcommits.org/) on `main`: `fix:` makes a patch release, `feat:` a minor one (while below 1.0), and `feat!:` or a `BREAKING CHANGE:` footer a major one. release-please keeps a release PR open with the next version and its changelog; merging it tags the release, and the workflow then attaches the binaries for Linux (amd64, armv6, aarch64) and macOS (arm64) together with `checksum.sha256`, signed keyless with [cosign](https://github.com/sigstore/cosign) through GitHub OIDC. A [signify](https://man.openbsd.org/signify) signature (`checksum.sha256.sig`) is added afterwards with `make signed-release`, which rebuilds the tag locally and only signs if the result is byte-identical to the published release.

Builds are reproducible: the Makefile pins the Go toolchain from `go.mod` and strips paths, VCS data and build IDs, so `make release` on a tag produces the same binaries on any host.

### Verifying a release

```sh
# cosign: made by this repository's release workflow
cosign verify-blob checksum.sha256 \
  --bundle checksum.sha256.sigstore.json \
  --certificate-identity "https://github.com/soerenschneider/kibotos/.github/workflows/release-please.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

# signify
signify -V -p kibotos.pub -m checksum.sha256

# then the binaries themselves
sha256sum --ignore-missing -c checksum.sha256
```
