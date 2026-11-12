// kibotos exports Vault/OpenBao KV (v1 and v2) secrets as plain JSON to stdout,
// and restores them from such a file.
//
// Usage:
//
//	restic backup --stdin-filename kibotos.json --stdin-from-command -- kibotos -config config.json
//	restic dump latest /kibotos.json | kibotos -config config.json -restore -
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	Address            string   `json:"address"`
	Namespace          string   `json:"namespace"`
	AppRoleMount       string   `json:"approle_mount"`
	RoleID             string   `json:"role_id"`
	SecretID           string   `json:"secret_id"`
	SecretIDFile       string   `json:"secret_id_file"`
	Token              string   `json:"-"` // from VAULT_TOKEN only, used instead of AppRole
	InsecureSkipVerify bool     `json:"insecure_skip_verify"`
	Timeout            string   `json:"timeout"`
	Paths              []string `json:"paths"`
}

type client struct {
	addr      string
	namespace string
	http      *http.Client

	token     string
	lease     time.Duration // token TTL granted at login
	renewable bool
	renewAt   time.Time
}

// authInfo is the "auth" block of login and renew responses.
type authInfo struct {
	ClientToken   string `json:"client_token"`
	LeaseDuration int    `json:"lease_duration"`
	Renewable     bool   `json:"renewable"`
}

// secret is one entry of a backup, keyed by its full path.
type secret struct {
	Data     map[string]any `json:"data"`
	Metadata *metadata      `json:"metadata,omitempty"` // KV v2 only
}

// metadata holds the writable per-secret KV v2 settings.
type metadata struct {
	MaxVersions        int               `json:"max_versions"`
	CASRequired        bool              `json:"cas_required"`
	DeleteVersionAfter string            `json:"delete_version_after"`
	CustomMetadata     map[string]string `json:"custom_metadata"`
}

var (
	errNotFound      = errors.New("not found")
	errConfig        = errors.New("config")
	errNoToken       = errors.New("no client token in response")
	errNotKV         = errors.New("not kv")
	errNoData        = errors.New(`no "data" object`)
	errNotSecretPath = errors.New("not a secret path")
	errTransport     = errors.New("http.DefaultTransport is not an *http.Transport")
)

// apiError is a non-2xx response from Vault.
type apiError struct {
	method, path, status string
	code                 int
	errors               []string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("%s %s: %s: %s", e.method, e.path, e.status, strings.TrimSpace(strings.Join(e.errors, "; ")))
}

// isForbidden reports whether err is Vault denying access.
func isForbidden(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.code == http.StatusForbidden
}

// isCASMismatch reports whether err is Vault rejecting a KV v2 write because its cas
// does not match the secret's current version.
func isCASMismatch(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.code == http.StatusBadRequest &&
		slices.ContainsFunc(ae.errors, func(s string) bool {
			return strings.Contains(s, "check-and-set parameter did not match")
		})
}

// KV engine versions.
const (
	kvV1 = 1
	kvV2 = 2
)

const (
	// Transient failures (network errors, 412, 429, 5xx) are retried with exponential backoff.
	maxAttempts = 4
	// The token is renewed once 1/renewDivisor of its TTL has passed.
	renewDivisor  = 2
	revokeTimeout = 5 * time.Second
)

var retryDelay = time.Second //nolint:gochecknoglobals // shortened by tests

// retryable marks an error from a single attempt that is worth retrying.
type retryable struct{ error }

// Set via -ldflags at build time.
var (
	BuildVersion = "dev"     //nolint:gochecknoglobals // set via -ldflags
	CommitHash   = "unknown" //nolint:gochecknoglobals // set via -ldflags
)

func main() {
	cfgPath := flag.String("config", "config.json", "path to JSON config file")
	restoreFrom := flag.String("restore", "",
		"restore secrets from this backup file (\"-\" for stdin) instead of backing up")
	version := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *version {
		fmt.Println(BuildVersion, CommitHash)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, *cfgPath, *restoreFrom, os.Stdin, os.Stdout)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "kibotos:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfgPath, restoreFrom string, stdin io.Reader, stdout io.Writer) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	if restoreFrom == "" && len(cfg.Paths) == 0 {
		return fmt.Errorf("%w: at least one path is required", errConfig)
	}

	// Read the backup before logging in, so a bad file fails without touching Vault.
	var backup map[string]secret
	if restoreFrom != "" {
		if backup, err = readBackup(restoreFrom, stdin); err != nil {
			return err
		}
	}

	c, err := newClient(cfg)
	if err != nil {
		return err
	}

	if cfg.Token != "" {
		// The token belongs to the caller, so it is neither renewed nor revoked.
		if err = c.useToken(ctx, cfg.Token); err != nil {
			return fmt.Errorf("token lookup: %w", err)
		}
	} else {
		if err = c.login(ctx, cfg.AppRoleMount, cfg.RoleID, cfg.SecretID); err != nil {
			return fmt.Errorf("approle login: %w", err)
		}
		defer c.revoke(ctx)
	}

	if restoreFrom != "" {
		return c.restore(ctx, backup)
	}

	result := map[string]secret{}
	for _, p := range cfg.Paths {
		if err = c.export(ctx, p, result); err != nil {
			return fmt.Errorf("export %q: %w", p, err)
		}
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // keep values like "<b>&" readable in the backup
	if err = enc.Encode(result); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := &Config{AppRoleMount: "approle", Timeout: "30s"}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields() // catch typos like "namspace"
	if err = dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Allow credentials to be kept out of the config file.
	cfg.Token = os.Getenv("VAULT_TOKEN")
	if v := os.Getenv("VAULT_ROLE_ID"); v != "" {
		cfg.RoleID = v
	}
	if err = resolveSecretID(cfg); err != nil {
		return nil, err
	}

	switch {
	case cfg.Address == "":
		return nil, fmt.Errorf("%w: address is required", errConfig)
	case cfg.Token != "" && (cfg.RoleID != "" || cfg.SecretID != ""):
		return nil, fmt.Errorf("%w: VAULT_TOKEN and AppRole credentials are both set, unset one", errConfig)
	case cfg.Token == "" && (cfg.RoleID == "" || cfg.SecretID == ""):
		return nil, fmt.Errorf(
			"%w: VAULT_TOKEN, or role_id and secret_id (or secret_id_file), are required", errConfig)
	}
	return cfg, nil
}

// resolveSecretID sets cfg.SecretID from, in order of precedence, VAULT_SECRET_ID or
// VAULT_SECRET_ID_FILE, then secret_id or secret_id_file in the config. Setting both a
// value and a file at the same level is an error rather than a silent choice.
func resolveSecretID(cfg *Config) error {
	if v, f := os.Getenv("VAULT_SECRET_ID"), os.Getenv("VAULT_SECRET_ID_FILE"); v != "" || f != "" {
		if v != "" && f != "" {
			return fmt.Errorf("%w: set only one of VAULT_SECRET_ID and VAULT_SECRET_ID_FILE", errConfig)
		}
		cfg.SecretID, cfg.SecretIDFile = v, f
	}
	if cfg.SecretIDFile == "" {
		return nil
	}
	if cfg.SecretID != "" {
		return fmt.Errorf("%w: set only one of secret_id and secret_id_file", errConfig)
	}
	b, err := os.ReadFile(filepath.Clean(cfg.SecretIDFile))
	if err != nil {
		return fmt.Errorf("%w: secret_id_file: %w", errConfig, err)
	}
	// Files written by editors or "echo" end with a newline that is not part of the ID.
	cfg.SecretID = strings.TrimSpace(string(b))
	if cfg.SecretID == "" {
		return fmt.Errorf("%w: secret_id_file %q is empty", errConfig, cfg.SecretIDFile)
	}
	return nil
}

func newClient(cfg *Config) (*client, error) {
	timeout, err := time.ParseDuration(cfg.Timeout)
	if err != nil {
		return nil, fmt.Errorf("config: timeout: %w", err)
	}

	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errTransport
	}
	transport := base.Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // explicit opt-in via config
	}

	return &client{
		addr:      strings.TrimRight(cfg.Address, "/"),
		namespace: cfg.Namespace,
		http:      &http.Client{Timeout: timeout, Transport: transport},
	}, nil
}

// do performs a request against /v1/<path> and decodes the response into out (if non-nil).
// Transient failures are retried; the token is renewed first once half its TTL has passed.
func (c *client) do(ctx context.Context, method, path string, body, out any) error {
	if c.renewable && time.Now().After(c.renewAt) {
		if err := c.renew(ctx); err != nil {
			return fmt.Errorf("renew token: %w", err)
		}
	}

	var b []byte
	if body != nil {
		var err error
		if b, err = json.Marshal(body); err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
	}

	delay := retryDelay
	for attempt := 1; ; attempt++ {
		err := c.attempt(ctx, method, path, b, out)
		var re retryable
		if !errors.As(err, &re) {
			return err
		}
		if attempt == maxAttempts {
			return re.error
		}
		select {
		case <-ctx.Done():
			return re.error
		case <-time.After(delay):
		}
		delay *= 2
	}
}

func (c *client) attempt(ctx context.Context, method, path string, body []byte, out any) error {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.addr+"/v1/"+path, r)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("X-Vault-Token", c.token)
	}
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%s %s: %w", method, path, ctx.Err())
		}
		return retryable{err}
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusNotFound {
		return errNotFound
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e) // best effort: the status alone is still reported
		err := &apiError{method: method, path: path, status: resp.Status, code: resp.StatusCode, errors: e.Errors}
		switch resp.StatusCode {
		case http.StatusPreconditionFailed, http.StatusTooManyRequests, http.StatusInternalServerError,
			http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return retryable{err}
		}
		return err
	}
	if out == nil {
		return nil
	}
	return decodeJSON(resp.Body, out)
}

func (c *client) login(ctx context.Context, mount, roleID, secretID string) error {
	var resp struct {
		Auth authInfo `json:"auth"`
	}
	body := map[string]string{"role_id": roleID, "secret_id": secretID}
	if err := c.do(ctx, "POST", "auth/"+strings.Trim(mount, "/")+"/login", body, &resp); err != nil {
		return err
	}
	if resp.Auth.ClientToken == "" {
		return errNoToken
	}
	c.token = resp.Auth.ClientToken
	c.lease = time.Duration(resp.Auth.LeaseDuration) * time.Second
	c.renewable = resp.Auth.Renewable && c.lease > 0
	c.renewAt = time.Now().Add(c.lease / renewDivisor)
	return nil
}

// useToken authenticates with an existing token and checks that Vault accepts it.
// The token is not renewed: a run cannot outlast the token's TTL.
func (c *client) useToken(ctx context.Context, token string) error {
	c.token = token
	return c.do(ctx, "GET", "auth/token/lookup-self", nil, nil)
}

// renew extends the token so long backups do not outlive it. Once the token
// hits its max TTL, renewal can no longer extend it and is not tried again.
func (c *client) renew(ctx context.Context) error {
	c.renewable = false // keeps do from recursing into renew
	var resp struct {
		Auth authInfo `json:"auth"`
	}
	if err := c.do(ctx, "POST", "auth/token/renew-self", nil, &resp); err != nil {
		return err
	}
	lease := time.Duration(resp.Auth.LeaseDuration) * time.Second
	c.renewable = resp.Auth.Renewable && lease >= c.lease
	c.renewAt = time.Now().Add(lease / renewDivisor)
	return nil
}

// revoke invalidates the token. It runs even after ctx is canceled (e.g. on SIGTERM),
// bounded by its own short timeout.
func (c *client) revoke(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revokeTimeout)
	defer cancel()
	c.renewable = false
	_ = c.attempt(ctx, "POST", "auth/token/revoke-self", nil, nil) // best effort: the token expires anyway
}

// mountData is the "data" block of a sys/internal/ui/mounts response.
type mountData struct {
	Path    string            `json:"path"`
	Type    string            `json:"type"`
	Options map[string]string `json:"options"`
}

// mountInfo returns the KV mount path (with trailing slash) and KV version for p.
func (c *client) mountInfo(ctx context.Context, p string) (string, int, error) {
	var resp struct {
		Data mountData `json:"data"`
	}
	if err := c.do(ctx, "GET", "sys/internal/ui/mounts/"+escapePath(p), nil, &resp); err != nil {
		return "", 0, fmt.Errorf("detect mount: %w", err)
	}
	if resp.Data.Type != "kv" && resp.Data.Type != "generic" {
		return "", 0, fmt.Errorf("mount %q is %q: %w", resp.Data.Path, resp.Data.Type, errNotKV)
	}
	version := kvV1
	if resp.Data.Options["version"] == "2" {
		version = kvV2
	}
	return resp.Data.Path, version, nil
}

func (c *client) export(ctx context.Context, p string, result map[string]secret) error {
	dirOnly := strings.HasSuffix(p, "/")
	p = strings.Trim(p, "/")
	mount, version, err := c.mountInfo(ctx, p)
	if err != nil {
		return err
	}
	rel := strings.TrimPrefix(p+"/", mount)
	rel = strings.TrimSuffix(rel, "/")

	// A configured path may point to a directory or to a single secret.
	keys, err := c.list(ctx, mount, version, rel)
	if errors.Is(err, errNotFound) {
		if rel == "" {
			return nil // empty mount
		}
		return c.collect(ctx, mount, version, rel, result)
	}
	if err != nil {
		return err
	}
	// A name can be both a secret and a directory ("app" and "app/"). Without a trailing
	// slash the path covers both; access to the secret itself is optional, since a policy
	// may only grant the directory.
	if rel != "" && !dirOnly {
		if err = c.collect(ctx, mount, version, rel, result); err != nil && !isForbidden(err) {
			return err
		}
	}
	return c.walk(ctx, mount, version, rel, keys, result)
}

func (c *client) walk(
	ctx context.Context,
	mount string,
	version int,
	dir string,
	keys []string,
	result map[string]secret,
) error {
	for _, k := range keys {
		p := k
		if dir != "" {
			p = dir + "/" + k
		}
		if !strings.HasSuffix(k, "/") {
			if err := c.collect(ctx, mount, version, p, result); err != nil {
				return err
			}
			continue
		}
		p = strings.TrimSuffix(p, "/")
		sub, err := c.list(ctx, mount, version, p)
		if errors.Is(err, errNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if err = c.walk(ctx, mount, version, p, sub, result); err != nil {
			return err
		}
	}
	return nil
}

func (c *client) collect(ctx context.Context, mount string, version int, p string, result map[string]secret) error {
	data, err := c.read(ctx, mount, version, p)
	if errors.Is(err, errNotFound) {
		return nil // deleted (v2) or vanished during the walk
	}
	if err != nil {
		return err
	}
	if data == nil {
		return nil
	}
	s := secret{Data: data}
	if version == kvV2 {
		var md *storedMetadata
		if md, err = c.readMetadata(ctx, mount, p); err != nil {
			return fmt.Errorf("read metadata: %w", err)
		}
		s.Metadata = &md.metadata
	}
	result[mount+p] = s
	return nil
}

// storedMetadata is the KV v2 metadata as Vault returns it: the writable settings plus the current version.
type storedMetadata struct {
	metadata

	CurrentVersion int `json:"current_version"`
}

func (c *client) readMetadata(ctx context.Context, mount, p string) (*storedMetadata, error) {
	var resp struct {
		Data storedMetadata `json:"data"`
	}
	if err := c.do(ctx, "GET", escapePath(mount+"metadata/"+p), nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// listData is the "data" block of a LIST response.
type listData struct {
	Keys []string `json:"keys"`
}

func (c *client) list(ctx context.Context, mount string, version int, dir string) ([]string, error) {
	path := mount + dir
	if version == kvV2 {
		path = mount + "metadata/" + dir
	}
	var resp struct {
		Data listData `json:"data"`
	}
	if err := c.do(ctx, "LIST", escapePath(path), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data.Keys, nil
}

func (c *client) read(ctx context.Context, mount string, version int, p string) (map[string]any, error) {
	path := mount + p
	if version == kvV2 {
		path = mount + "data/" + p
	}
	var resp struct {
		Data json.RawMessage `json:"data"`
	}
	if err := c.do(ctx, "GET", escapePath(path), nil, &resp); err != nil {
		return nil, err
	}
	if version == kvV1 {
		var data map[string]any
		if err := decodeJSON(bytes.NewReader(resp.Data), &data); err != nil {
			return nil, err
		}
		return data, nil
	}
	var v2 struct {
		Data map[string]any `json:"data"`
	}
	if err := decodeJSON(bytes.NewReader(resp.Data), &v2); err != nil {
		return nil, err
	}
	return v2.Data, nil
}

func readBackup(path string, stdin io.Reader) (map[string]secret, error) {
	r := stdin
	if path != "-" {
		f, err := os.Open(filepath.Clean(path))
		if err != nil {
			return nil, fmt.Errorf("open backup: %w", err)
		}
		defer func() {
			_ = f.Close() // read-only, nothing to flush
		}()
		r = f
	}
	var backup map[string]secret
	if err := decodeJSON(r, &backup); err != nil {
		return nil, fmt.Errorf("parse backup: %w", err)
	}
	for p, s := range backup {
		if s.Data == nil {
			return nil, fmt.Errorf("parse backup: %q has %w", p, errNoData)
		}
	}
	return backup, nil
}

// restore writes every secret in backup to Vault, overwriting existing ones.
// Mounts must already exist; secrets not in the backup are left untouched.
func (c *client) restore(ctx context.Context, backup map[string]secret) error {
	paths := slices.Sorted(maps.Keys(backup))

	versions := map[string]int{} // mount -> KV version, so each mount is looked up once
	written := 0
	for _, p := range paths {
		mount, version, err := c.cachedMountInfo(ctx, p, versions)
		if err != nil {
			return fmt.Errorf("restore %q: %w", p, err)
		}
		rel := strings.TrimPrefix(p, mount)
		if rel == "" || rel == p {
			return fmt.Errorf("restore %q: %w inside mount %q", p, errNotSecretPath, mount)
		}
		changed, err := c.write(ctx, mount, version, rel, backup[p])
		if err != nil {
			return fmt.Errorf("restore %q: %w", p, err)
		}
		if changed {
			written++
		}
	}
	fmt.Fprintf(os.Stderr, "kibotos: restored %d secrets, %d already up to date\n", written, len(paths)-written)
	return nil
}

func (c *client) cachedMountInfo(ctx context.Context, p string, versions map[string]int) (string, int, error) {
	for m, v := range versions {
		if strings.HasPrefix(p, m) {
			return m, v, nil
		}
	}
	m, v, err := c.mountInfo(ctx, p)
	if err == nil {
		versions[m] = v
	}
	return m, v, err
}

// write restores one secret and reports whether it changed anything. On v2 the data is
// written with check-and-set against the current version, which works whether or not
// cas_required is set and fails instead of overwriting a concurrent change. Data and
// metadata that already match the backup are not rewritten, so restoring twice does not
// add versions. Metadata is only written once the data is in place, so a failed data
// write leaves the secret untouched.
func (c *client) write(ctx context.Context, mount string, version int, p string, s secret) (bool, error) {
	if version == kvV1 {
		if err := c.do(ctx, "POST", escapePath(mount+p), s.Data, nil); err != nil {
			return false, err
		}
		return true, nil
	}

	current := 0 // cas=0 means "only if the secret does not exist yet"
	stored, err := c.readMetadata(ctx, mount, p)
	switch {
	case err == nil:
		current = stored.CurrentVersion
	case errors.Is(err, errNotFound):
		stored = nil // new secret, keep cas=0
	default:
		return false, fmt.Errorf("read metadata: %w", err)
	}

	dataChanged, err := c.writeData(ctx, mount, p, s.Data, current)
	if err != nil {
		return false, err
	}
	metaChanged, err := c.writeMetadata(ctx, mount, p, s.Metadata, stored)
	if err != nil {
		return dataChanged, err
	}
	return dataChanged || metaChanged, nil
}

// writeData writes a new v2 version with check-and-set against version current, unless
// that version already holds the same data.
func (c *client) writeData(ctx context.Context, mount, p string, data map[string]any, current int) (bool, error) {
	if current > 0 {
		same, err := c.hasData(ctx, mount, p, data)
		if err != nil {
			return false, err
		}
		if same {
			return false, nil
		}
	}

	body := map[string]any{"data": data, "options": map[string]int{"cas": current}}
	err := c.do(ctx, "POST", escapePath(mount+"data/"+p), body, nil)
	if isCASMismatch(err) {
		// A retried write fails this way when an earlier attempt landed but its response
		// was lost. That is a success if the secret now holds exactly this data.
		if same, readErr := c.hasData(ctx, mount, p, data); readErr == nil && same {
			return true, nil
		}
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// hasData reports whether the current v2 version of p holds data.
func (c *client) hasData(ctx context.Context, mount, p string, data map[string]any) (bool, error) {
	existing, err := c.read(ctx, mount, kvV2, p)
	switch {
	case errors.Is(err, errNotFound):
		return false, nil // current version deleted or destroyed
	case err != nil:
		return false, fmt.Errorf("read current data: %w", err)
	}
	return sameJSON(existing, data), nil
}

// writeMetadata replaces the v2 settings of p with md, unless stored already matches.
// Existing custom metadata is cleared when md has none.
func (c *client) writeMetadata(
	ctx context.Context,
	mount, p string,
	md *metadata,
	stored *storedMetadata,
) (bool, error) {
	if md == nil {
		return false, nil
	}
	want := *md
	if want.CustomMetadata == nil {
		want.CustomMetadata = map[string]string{} // an empty object clears it, null would keep it
	}
	if stored != nil && sameMetadata(&want, &stored.metadata) {
		return false, nil
	}
	if err := c.do(ctx, "POST", escapePath(mount+"metadata/"+p), want, nil); err != nil {
		return false, fmt.Errorf("write metadata: %w", err)
	}
	return true, nil
}

func sameMetadata(a, b *metadata) bool {
	return a.MaxVersions == b.MaxVersions && a.CASRequired == b.CASRequired &&
		a.DeleteVersionAfter == b.DeleteVersionAfter && maps.Equal(a.CustomMetadata, b.CustomMetadata)
}

// sameJSON compares values decoded by decodeJSON. Numbers are equal when their float64
// values are, since that is all KV v2 stores ("1.0" is read back as 1).
func sameJSON(a, b any) bool {
	switch av := a.(type) {
	case map[string]any:
		bm, ok := b.(map[string]any)
		if !ok || len(av) != len(bm) {
			return false
		}
		for k, v := range av {
			if bv, found := bm[k]; !found || !sameJSON(v, bv) {
				return false
			}
		}
		return true
	case []any:
		bs, ok := b.([]any)
		return ok && slices.EqualFunc(av, bs, sameJSON)
	case json.Number:
		bn, ok := b.(json.Number)
		if !ok {
			return false
		}
		af, aErr := av.Float64()
		bf, bErr := bn.Float64()
		return aErr == nil && bErr == nil && af == bf
	default:
		return a == b
	}
}

// decodeJSON keeps numbers as json.Number so large integers survive a backup/restore round trip.
func decodeJSON(r io.Reader, v any) error {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decode json: %w", err)
	}
	return nil
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}
