package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	retryDelay = time.Millisecond
	m.Run()
}

// fakeVault is a minimal in-memory Vault that speaks just enough of the API for kibotos.
type fakeVault struct {
	mounts    map[string]int            // mount path ("secret/") -> KV version
	secrets   map[string]map[string]any // full logical path ("secret/app/db") -> data
	meta      map[string]*metadata      // v2 per-secret metadata
	versions  map[string]int            // v2 current version; secrets not listed here are at version 1
	deleted   map[string]bool           // v2 secrets that are soft-deleted
	forbidden map[string]bool           // API paths (after /v1/), optionally prefixed with "METHOD ", that return 403
	mu        sync.Mutex
	revoked   bool
	requests  []string

	leaseSeconds      int    // token TTL returned by login; 0 = not renewable
	renewSeconds      int    // TTL returned by renew-self
	renewals          int    // number of renew-self calls
	afterMetadataRead func() // called after serving a v2 metadata read
}

const (
	testRoleID   = "role"
	testSecretID = "secret"
	testToken    = "s.token"
)

func newFakeVault() *fakeVault {
	return &fakeVault{
		mounts: map[string]int{"secret/": 2, "kv1/": 1, "team/kv/": 2, "empty/": 2},
		secrets: map[string]map[string]any{
			"secret/app/db":     {"user": "admin", "pass": "s3cr3t"},
			"secret/app/api":    {"token": "abc"},
			"secret/top":        {"n": float64(1)},
			"secret/odd name/x": {"a": "1"},
			"secret/gone":       {"x": "1"},
			"kv1/team-a/one":    {"k": "v"},
			"kv1/team-b/two":    {"k": "v"},
			"team/kv/nested/s":  {"deep": true},
		},
		meta: map[string]*metadata{
			"secret/app/db": {
				MaxVersions:        5,
				CASRequired:        true,
				DeleteVersionAfter: "1h0m0s",
				CustomMetadata:     map[string]string{"owner": "team-a"},
			},
		},
		deleted:   map[string]bool{"secret/gone": true},
		forbidden: map[string]bool{},
	}
}

func (f *fakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+path)
	f.mu.Unlock()

	if r.Method == http.MethodPost && path == "auth/approle/login" {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["role_id"] != testRoleID || body["secret_id"] != testSecretID {
			writeJSON(w, 400, map[string]any{"errors": []string{"invalid role or secret ID"}})
			return
		}
		writeJSON(w, 200, map[string]any{"auth": map[string]any{
			"client_token": testToken, "lease_duration": f.leaseSeconds, "renewable": f.leaseSeconds > 0,
		}})
		return
	}

	if r.Header.Get("X-Vault-Token") != testToken || f.forbidden[path] || f.forbidden[r.Method+" "+path] {
		writeJSON(w, 403, map[string]any{"errors": []string{"1 error occurred:\n\t* permission denied\n\n"}})
		return
	}

	switch {
	case r.Method == http.MethodPost && path == "auth/token/renew-self":
		f.mu.Lock()
		f.renewals++
		f.mu.Unlock()
		writeJSON(w, 200, map[string]any{"auth": map[string]any{
			"client_token": testToken, "lease_duration": f.renewSeconds, "renewable": true,
		}})
	case r.Method == http.MethodPost && path == "auth/token/revoke-self":
		f.mu.Lock()
		f.revoked = true
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "sys/internal/ui/mounts/"):
		f.serveMount(w, strings.TrimPrefix(path, "sys/internal/ui/mounts/"))
	case r.Method == "LIST":
		f.serveList(w, path)
	case r.Method == http.MethodGet:
		f.serveRead(w, path)
	case r.Method == http.MethodPost || r.Method == http.MethodPut:
		f.serveWrite(w, r, path)
	default:
		writeJSON(w, 405, map[string]any{"errors": []string{"unsupported"}})
	}
}

func (f *fakeVault) findMount(p string) (string, int, bool) {
	for m, v := range f.mounts {
		if strings.HasPrefix(p+"/", m) {
			return m, v, true
		}
	}
	return "", 0, false
}

func (f *fakeVault) serveMount(w http.ResponseWriter, p string) {
	m, v, ok := f.findMount(p)
	if !ok {
		writeJSON(w, 400, map[string]any{"errors": []string{"no mount"}})
		return
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"path": m, "type": "kv", "options": map[string]string{"version": map[int]string{1: "1", 2: "2"}[v]},
	}})
}

// split maps an API path to its logical secret path and, for v2, the "data" or "metadata" segment.
func (f *fakeVault) split(apiPath string) (string, string, bool) {
	apiPath = strings.TrimSuffix(apiPath, "/")
	m, v, ok := f.findMount(apiPath)
	if !ok {
		return "", "", false
	}
	rest := strings.TrimPrefix(apiPath+"/", m)
	var seg string
	if v == 2 {
		seg, rest, ok = strings.Cut(rest, "/")
		if !ok || (seg != "data" && seg != "metadata") {
			return "", "", false
		}
	}
	return strings.TrimSuffix(m+rest, "/"), seg, true
}

func (f *fakeVault) currentVersion(p string) int {
	if v, ok := f.versions[p]; ok {
		return v
	}
	if _, ok := f.secrets[p]; ok {
		return 1
	}
	return 0
}

func (f *fakeVault) metadataFor(p string) metadata {
	if md := f.meta[p]; md != nil {
		return *md
	}
	return metadata{DeleteVersionAfter: "0s"}
}

func (f *fakeVault) serveList(w http.ResponseWriter, apiPath string) {
	dir, seg, ok := f.split(apiPath)
	if !ok || seg == "data" {
		writeJSON(w, 404, map[string]any{"errors": []string{}})
		return
	}
	set := map[string]bool{}
	for p := range f.secrets {
		if !strings.HasPrefix(p, dir+"/") {
			continue
		}
		rest := strings.TrimPrefix(p, dir+"/")
		if i := strings.Index(rest, "/"); i >= 0 {
			set[rest[:i+1]] = true
		} else {
			set[rest] = true
		}
	}
	if len(set) == 0 {
		writeJSON(w, 404, map[string]any{"errors": []string{}})
		return
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	writeJSON(w, 200, map[string]any{"data": map[string]any{"keys": keys}})
}

func (f *fakeVault) serveRead(w http.ResponseWriter, apiPath string) {
	p, seg, ok := f.split(apiPath)
	data, exists := f.secrets[p]
	if seg == "metadata" && f.afterMetadataRead != nil {
		defer f.afterMetadataRead()
	}
	if seg == "metadata" && (exists || f.meta[p] != nil) {
		// Includes read-only fields that a backup must not pick up.
		md := f.metadataFor(p)
		writeJSON(w, 200, map[string]any{"data": map[string]any{
			"max_versions":         md.MaxVersions,
			"cas_required":         md.CASRequired,
			"delete_version_after": md.DeleteVersionAfter,
			"custom_metadata":      md.CustomMetadata,
			"current_version": f.currentVersion(
				p,
			),
			"created_time": "2026-01-01T00:00:00Z",
			"versions":     map[string]any{},
		}})
		return
	}
	if !ok || seg == "metadata" || !exists || f.deleted[p] {
		writeJSON(w, 404, map[string]any{"errors": []string{}})
		return
	}
	if _, v, _ := f.findMount(p); v == 2 {
		writeJSON(
			w,
			200,
			map[string]any{"data": map[string]any{"data": data, "metadata": map[string]any{"version": 1}}},
		)
		return
	}
	writeJSON(w, 200, map[string]any{"data": data})
}

func (f *fakeVault) serveWrite(w http.ResponseWriter, r *http.Request, apiPath string) {
	p, seg, ok := f.split(apiPath)
	if !ok {
		writeJSON(w, 404, map[string]any{"errors": []string{}})
		return
	}
	b, _ := io.ReadAll(r.Body)
	if seg == "metadata" {
		// Like Vault, only the fields present in the request are changed.
		md := f.metadataFor(p)
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(b, &fields)
		if _, found := fields["custom_metadata"]; found {
			md.CustomMetadata = nil // replaced, not merged
		}
		if err := json.Unmarshal(b, &md); err != nil {
			writeJSON(w, 400, map[string]any{"errors": []string{err.Error()}})
			return
		}
		if len(md.CustomMetadata) == 0 {
			md.CustomMetadata = nil
		}
		f.mu.Lock()
		f.meta[p] = &md
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var body map[string]any
	if err := decodeJSON(bytes.NewReader(b), &body); err != nil {
		writeJSON(w, 400, map[string]any{"errors": []string{err.Error()}})
		return
	}
	if seg == "data" {
		cas, hasCAS := casOption(body)
		if f.metadataFor(p).CASRequired && !hasCAS {
			writeJSON(w, 400, map[string]any{"errors": []string{"check-and-set parameter required for this call"}})
			return
		}
		if hasCAS && cas.String() != strconv.Itoa(f.currentVersion(p)) {
			writeJSON(
				w,
				400,
				map[string]any{"errors": []string{"check-and-set parameter did not match the current version"}},
			)
			return
		}
		data, isMap := body["data"].(map[string]any)
		if !isMap {
			writeJSON(w, 400, map[string]any{"errors": []string{"no data provided"}})
			return
		}
		body = data
	}
	f.mu.Lock()
	if seg == "data" {
		if f.versions == nil {
			f.versions = map[string]int{}
		}
		f.versions[p] = f.currentVersion(p) + 1
	}
	f.secrets[p] = body
	delete(f.deleted, p)
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// casOption returns the "cas" option of a KV v2 write, if set.
func casOption(body map[string]any) (json.Number, bool) {
	opts, ok := body["options"].(map[string]any)
	if !ok {
		return "", false
	}
	cas, ok := opts["cas"].(json.Number)
	return cas, ok
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // test fixtures are always encodable
	}
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func writeConfig(t *testing.T, cfg map[string]any) string {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "config.json")
	if err = os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func runBackup(t *testing.T, fv *fakeVault, paths ...string) (map[string]secret, error) {
	t.Helper()
	srv := httptest.NewServer(fv)
	t.Cleanup(srv.Close)
	cfg := writeConfig(t, map[string]any{
		"address": srv.URL, "role_id": testRoleID, "secret_id": testSecretID, "paths": paths,
	})
	var out bytes.Buffer
	if err := run(t.Context(), cfg, "", nil, &out); err != nil {
		return nil, err
	}
	var got map[string]secret
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}
	return got, nil
}

func TestExport(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		paths []string
		want  []string
	}{
		{
			"whole v2 mount",
			[]string{"secret"},
			[]string{"secret/app/api", "secret/app/db", "secret/odd name/x", "secret/top"},
		},
		{
			"v2 mount with trailing slash",
			[]string{"secret/"},
			[]string{"secret/app/api", "secret/app/db", "secret/odd name/x", "secret/top"},
		},
		{"v2 subdirectory", []string{"secret/app"}, []string{"secret/app/api", "secret/app/db"}},
		{"v2 single secret", []string{"secret/app/db"}, []string{"secret/app/db"}},
		{"whole v1 mount", []string{"kv1"}, []string{"kv1/team-a/one", "kv1/team-b/two"}},
		{"v1 subdirectory", []string{"kv1/team-a"}, []string{"kv1/team-a/one"}},
		{"v1 single secret", []string{"kv1/team-a/one"}, []string{"kv1/team-a/one"}},
		{"multi-segment mount", []string{"team/kv"}, []string{"team/kv/nested/s"}},
		{"overlapping paths", []string{"secret/app", "secret/app/db"}, []string{"secret/app/api", "secret/app/db"}},
		{"multiple mounts", []string{"kv1/team-b", "secret/top"}, []string{"kv1/team-b/two", "secret/top"}},
		{"nonexistent path in mount", []string{"secret/nope"}, []string{}},
		{"empty mount", []string{"empty"}, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fv := newFakeVault()
			got, err := runBackup(t, fv, tt.paths...)
			if err != nil {
				t.Fatal(err)
			}
			keys := make([]string, 0, len(got))
			for k := range got {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			if !reflect.DeepEqual(keys, tt.want) {
				t.Errorf("keys = %q, want %q", keys, tt.want)
			}
			for k, v := range got {
				if !reflect.DeepEqual(v.Data, fv.secrets[k]) {
					t.Errorf("%s data = %v, want %v", k, v.Data, fv.secrets[k])
				}
				_, version, _ := fv.findMount(k)
				if version == 1 && v.Metadata != nil {
					t.Errorf("%s: v1 secret has metadata %+v", k, v.Metadata)
				}
				want := fv.metadataFor(k)
				if version == 2 && (v.Metadata == nil || !reflect.DeepEqual(*v.Metadata, want)) {
					t.Errorf("%s metadata = %+v, want %+v", k, v.Metadata, want)
				}
			}
			if !fv.revoked {
				t.Error("token was not revoked")
			}
		})
	}
}

func TestExportSkipsDeletedSecret(t *testing.T) {
	t.Parallel()
	got, err := runBackup(t, newFakeVault(), "secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["secret/gone"]; ok {
		t.Error("soft-deleted secret was exported")
	}
}

func TestExportForbidden(t *testing.T) {
	t.Parallel()
	fv := newFakeVault()
	fv.forbidden["secret/data/app/db"] = true
	_, err := runBackup(t, fv, "secret")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "403") || strings.HasSuffix(err.Error(), "\n") {
		t.Errorf("unexpected error: %q", err)
	}
	if !fv.revoked {
		t.Error("token was not revoked after failure")
	}
}

func TestExportMetadataForbidden(t *testing.T) {
	t.Parallel()
	fv := newFakeVault()
	fv.forbidden["GET secret/metadata/app/db"] = true
	_, err := runBackup(t, fv, "secret/app/db")
	if err == nil || !strings.Contains(err.Error(), "read metadata") {
		t.Fatalf("err = %v, want read metadata error", err)
	}
}

func TestExportNotKV(t *testing.T) {
	t.Parallel()
	fv := newFakeVault()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/sys/internal/ui/mounts/") {
			writeJSON(w, 200, map[string]any{"data": map[string]any{"path": "pki/", "type": "pki"}})
			return
		}
		fv.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	cfg := writeConfig(
		t,
		map[string]any{"address": srv.URL, "role_id": testRoleID, "secret_id": testSecretID, "paths": []string{"pki"}},
	)
	err := run(t.Context(), cfg, "", nil, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "not kv") {
		t.Fatalf("err = %v, want 'not kv'", err)
	}
}

func TestLoginFailure(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(newFakeVault())
	t.Cleanup(srv.Close)
	cfg := writeConfig(
		t,
		map[string]any{"address": srv.URL, "role_id": "wrong", "secret_id": "wrong", "paths": []string{"secret"}},
	)
	err := run(t.Context(), cfg, "", nil, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "approle login") {
		t.Fatalf("err = %v, want approle login error", err)
	}
}

func TestBackupRequiresPaths(t *testing.T) {
	t.Parallel()
	cfg := writeConfig(t, map[string]any{"address": "http://x", "role_id": "r", "secret_id": "s"})
	err := run(t.Context(), cfg, "", nil, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "path") {
		t.Fatalf("err = %v, want missing path error", err)
	}
}

func restoreFakeVault(t *testing.T, fv *fakeVault, backup string) error {
	t.Helper()
	srv := httptest.NewServer(fv)
	t.Cleanup(srv.Close)
	// No paths: restore must not require them.
	cfg := writeConfig(t, map[string]any{"address": srv.URL, "role_id": testRoleID, "secret_id": testSecretID})
	return run(t.Context(), cfg, "-", strings.NewReader(backup), nil)
}

func TestRestore(t *testing.T) {
	t.Parallel()
	fv := newFakeVault()
	fv.secrets = map[string]map[string]any{
		"secret/keep":       {"a": "b"},
		"secret/app/db":     {"old": "x"},
		"secret/odd name/x": {"old": "y"},
	}
	// Existing secrets with settings that must be replaced; app/db would reject a plain write.
	fv.meta = map[string]*metadata{
		"secret/app/db":     {CASRequired: true, MaxVersions: 2, CustomMetadata: map[string]string{"stale": "1"}},
		"secret/odd name/x": {CustomMetadata: map[string]string{"stale": "1"}},
	}
	backup := `{
		"secret/app/db": {
			"data": {"user": "admin", "n": 9007199254740993, "nested": {"a": [1, "two"]}},
			"metadata": {"max_versions": 5, "cas_required": true, "delete_version_after": "1h0m0s", "custom_metadata": {"owner": "team-a"}}
		},
		"secret/odd name/x": {
			"data": {"k": "v"},
			"metadata": {"max_versions": 0, "cas_required": false, "delete_version_after": "0s", "custom_metadata": null}
		},
		"secret/no-meta":   {"data": {"k": "v"}},
		"kv1/team-a/one":   {"data": {"k": "v1"}, "metadata": {"max_versions": 3}},
		"team/kv/nested/s": {"data": {"deep": true}, "metadata": {"cas_required": true}}
	}`
	if err := restoreFakeVault(t, fv, backup); err != nil {
		t.Fatal(err)
	}

	want := map[string]map[string]any{
		"secret/keep": {"a": "b"}, // not in backup, left alone
		"secret/app/db": {
			"user":   "admin",
			"n":      json.Number("9007199254740993"),
			"nested": map[string]any{"a": []any{json.Number("1"), "two"}},
		},
		"secret/odd name/x": {"k": "v"},
		"secret/no-meta":    {"k": "v"},
		"kv1/team-a/one":    {"k": "v1"}, // metadata ignored on v1
		"team/kv/nested/s":  {"deep": true},
	}
	wantMeta := map[string]*metadata{
		"secret/app/db": {
			MaxVersions:        5,
			CASRequired:        true,
			DeleteVersionAfter: "1h0m0s",
			CustomMetadata:     map[string]string{"owner": "team-a"},
		},
		"secret/odd name/x": {DeleteVersionAfter: "0s"},
		"team/kv/nested/s":  {CASRequired: true},
	}
	if !reflect.DeepEqual(fv.meta, wantMeta) {
		for p := range wantMeta {
			if !reflect.DeepEqual(fv.meta[p], wantMeta[p]) {
				t.Errorf("metadata %s = %+v, want %+v", p, fv.meta[p], wantMeta[p])
			}
		}
		if len(fv.meta) != len(wantMeta) {
			t.Errorf("metadata written for %d secrets, want %d", len(fv.meta), len(wantMeta))
		}
	}
	if got, wantN := normJSON(t, fv.secrets), normJSON(t, want); !reflect.DeepEqual(got, wantN) {
		t.Errorf("secrets after restore:\ngot  %v\nwant %v", got, wantN)
	}
	if !fv.revoked {
		t.Error("token was not revoked")
	}
}

func TestRestoreRoundTrip(t *testing.T) {
	t.Parallel()
	src := newFakeVault()
	src.secrets["secret/big"] = map[string]any{"n": json.Number("9007199254740993")}
	src.meta["team/kv/nested/s"] = &metadata{
		MaxVersions:        2,
		DeleteVersionAfter: "30m0s",
		CustomMetadata:     map[string]string{"a": "b"},
	}
	srv := httptest.NewServer(src)
	t.Cleanup(srv.Close)
	cfg := writeConfig(t, map[string]any{
		"address":   srv.URL,
		"role_id":   testRoleID,
		"secret_id": testSecretID,
		"paths":     []string{"secret", "kv1", "team/kv"},
	})
	var first bytes.Buffer
	if err := run(t.Context(), cfg, "", nil, &first); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(first.String(), "9007199254740993") {
		t.Errorf("large integer lost precision in backup:\n%s", first.String())
	}

	dst := newFakeVault()
	dst.secrets = map[string]map[string]any{}
	dst.meta = map[string]*metadata{}
	dst.deleted = map[string]bool{}
	file := filepath.Join(t.TempDir(), "backup.json")
	if err := os.WriteFile(file, first.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	dstSrv := httptest.NewServer(dst)
	t.Cleanup(dstSrv.Close)
	dstCfg := writeConfig(t, map[string]any{
		"address":   dstSrv.URL,
		"role_id":   testRoleID,
		"secret_id": testSecretID,
		"paths":     []string{"secret", "kv1", "team/kv"},
	})
	if err := run(t.Context(), dstCfg, file, nil, nil); err != nil {
		t.Fatal(err)
	}
	var second bytes.Buffer
	if err := run(t.Context(), dstCfg, "", nil, &second); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Errorf("round trip mismatch:\nfirst  %s\nsecond %s", first.String(), second.String())
	}
}

func TestRestoreErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		backup string
		setup  func(*fakeVault)
		want   string
	}{
		{"invalid json", `{`, nil, "parse backup"},
		{"secret is not an object", `{"secret/a": "x"}`, nil, "parse backup"},
		{"secret without data", `{"secret/a": {"a": "b"}}`, nil, `no "data" object`},
		{"path is the mount itself", `{"secret": {"data": {"a": "b"}}}`, nil, "not a secret path"},
		{"unknown mount", `{"nope/a": {"data": {"a": "b"}}}`, nil, "detect mount"},
		{
			"write forbidden",
			`{"secret/a": {"data": {"a": "b"}}}`,
			func(f *fakeVault) { f.forbidden["secret/data/a"] = true },
			"403",
		},
		{
			"metadata write forbidden",
			`{"secret/a": {"data": {"a": "b"}, "metadata": {}}}`,
			func(f *fakeVault) { f.forbidden["POST secret/metadata/a"] = true },
			"write metadata",
		},
		{
			"metadata read forbidden",
			`{"secret/a": {"data": {"a": "b"}}}`,
			func(f *fakeVault) { f.forbidden["GET secret/metadata/a"] = true },
			"read metadata",
		},
		{"concurrent change", `{"secret/app/db": {"data": {"a": "b"}}}`, func(f *fakeVault) {
			f.afterMetadataRead = func() { f.versions = map[string]int{"secret/app/db": 7} } // someone writes in between
		}, "did not match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fv := newFakeVault()
			if tt.setup != nil {
				tt.setup(fv)
			}
			err := restoreFakeVault(t, fv, tt.backup)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestRestoreOverCASRequired(t *testing.T) {
	t.Parallel()
	fv := newFakeVault() // secret/app/db has cas_required set
	backup := `{"secret/app/db": {"data": {"new": "1"}}, "secret/fresh": {"data": {"a": "b"}}}`
	if err := restoreFakeVault(t, fv, backup); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fv.secrets["secret/app/db"], map[string]any{"new": "1"}) ||
		fv.versions["secret/app/db"] != 2 {
		t.Errorf("secret/app/db = %v (version %d)", fv.secrets["secret/app/db"], fv.versions["secret/app/db"])
	}
	if fv.versions["secret/fresh"] != 1 {
		t.Errorf("secret/fresh version = %d, want 1", fv.versions["secret/fresh"])
	}
	if !fv.metadataFor("secret/app/db").CASRequired {
		t.Error("cas_required was changed although the backup has no metadata")
	}
}

func TestRestoreFailedDataWriteLeavesMetadata(t *testing.T) {
	t.Parallel()
	fv := newFakeVault()
	before := fv.metadataFor("secret/app/db")
	fv.forbidden["POST secret/data/app/db"] = true
	err := restoreFakeVault(
		t,
		fv,
		`{"secret/app/db": {"data": {"a": "b"}, "metadata": {"max_versions": 1, "cas_required": false, "custom_metadata": null}}}`,
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if after := fv.metadataFor("secret/app/db"); !reflect.DeepEqual(after, before) {
		t.Errorf("metadata changed despite failed data write: %+v -> %+v", before, after)
	}
}

func TestRestoreBadFileDoesNotLogIn(t *testing.T) {
	t.Parallel()
	fv := newFakeVault()
	srv := httptest.NewServer(fv)
	t.Cleanup(srv.Close)
	cfg := writeConfig(t, map[string]any{"address": srv.URL, "role_id": testRoleID, "secret_id": testSecretID})
	if err := run(t.Context(), cfg, filepath.Join(t.TempDir(), "missing.json"), nil, nil); err == nil {
		t.Fatal("expected error")
	}
	if len(fv.requests) != 0 {
		t.Errorf("made requests despite unreadable backup: %v", fv.requests)
	}
}

// dropConnection closes the client connection without sending a response.
func dropConnection(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		panic("ResponseWriter cannot be hijacked")
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		panic(err)
	}
	_ = conn.Close()
}

// flaky returns a handler that answers the first n requests with status (0 = drop the connection).
func flaky(n, status int, next http.Handler) (http.Handler, *int) {
	var mu sync.Mutex
	calls := 0
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		fail := calls <= n
		mu.Unlock()
		if !fail {
			next.ServeHTTP(w, r)
			return
		}
		if status == 0 {
			dropConnection(w)
			return
		}
		writeJSON(w, status, map[string]any{"errors": []string{"transient"}})
	}), &calls
}

func TestRetry(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		failures  int
		status    int
		wantErr   string
		wantCalls int
	}{
		{"503 then success", 2, 503, "", 3},
		{"429 then success", 1, 429, "", 2},
		{"412 then success", 1, 412, "", 2},
		{"dropped connection then success", 2, 0, "", 3},
		{"gives up after max attempts", 100, 503, "503", maxAttempts},
		{"400 is not retried", 100, 400, "400", 1},
		{"403 is not retried", 100, 403, "403", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h, calls := flaky(tt.failures, tt.status, newFakeVault())
			srv := httptest.NewServer(h)
			t.Cleanup(srv.Close)
			c, err := newClient(&Config{Address: srv.URL, Timeout: "5s"})
			if err != nil {
				t.Fatal(err)
			}
			err = c.login(t.Context(), "approle", testRoleID, testSecretID)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
			if *calls != tt.wantCalls {
				t.Errorf("calls = %d, want %d", *calls, tt.wantCalls)
			}
		})
	}
}

func TestTokenRenewal(t *testing.T) {
	t.Parallel()
	fv := newFakeVault()
	fv.leaseSeconds, fv.renewSeconds = 3600, 3600
	srv := httptest.NewServer(fv)
	t.Cleanup(srv.Close)
	c, err := newClient(&Config{Address: srv.URL, Timeout: "5s"})
	if err != nil {
		t.Fatal(err)
	}
	if err = c.login(t.Context(), "approle", testRoleID, testSecretID); err != nil {
		t.Fatal(err)
	}
	if !c.renewable || time.Until(c.renewAt) < 29*time.Minute {
		t.Fatalf(
			"renewal not scheduled at half the TTL: renewable=%v renewAt in %v",
			c.renewable,
			time.Until(c.renewAt),
		)
	}

	if _, _, err = c.mountInfo(t.Context(), "secret"); err != nil {
		t.Fatal(err)
	}
	if fv.renewals != 0 {
		t.Fatal("renewed before half the TTL passed")
	}

	c.renewAt = time.Now().Add(-time.Second)
	if _, _, err = c.mountInfo(t.Context(), "secret"); err != nil {
		t.Fatal(err)
	}
	if fv.renewals != 1 || !c.renewable || time.Until(c.renewAt) < 29*time.Minute {
		t.Errorf("renewals=%d renewable=%v renewAt in %v", fv.renewals, c.renewable, time.Until(c.renewAt))
	}

	// Capped by max TTL: shorter lease than at login, so stop renewing.
	fv.renewSeconds = 60
	c.renewAt = time.Now().Add(-time.Second)
	for range 2 {
		if _, _, err = c.mountInfo(t.Context(), "secret"); err != nil {
			t.Fatal(err)
		}
	}
	if fv.renewals != 2 || c.renewable {
		t.Errorf("after cap: renewals=%d renewable=%v, want 2 and false", fv.renewals, c.renewable)
	}
}

func TestTokenNotRenewable(t *testing.T) {
	t.Parallel()
	fv := newFakeVault() // zero lease: the token is not renewable
	if _, err := runBackup(t, fv, "secret"); err != nil {
		t.Fatal(err)
	}
	if fv.renewals != 0 {
		t.Errorf("renewals = %d, want 0", fv.renewals)
	}
}

func TestCancelRevokesToken(t *testing.T) {
	t.Parallel()
	fv := newFakeVault()
	ctx, cancel := context.WithCancel(t.Context())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "LIST" {
			cancel() // simulate SIGTERM mid-backup
			writeJSON(w, 503, map[string]any{"errors": []string{"busy"}})
			return
		}
		fv.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	cfg := writeConfig(
		t,
		map[string]any{
			"address":   srv.URL,
			"role_id":   testRoleID,
			"secret_id": testSecretID,
			"paths":     []string{"secret"},
		},
	)
	var out bytes.Buffer
	if err := run(ctx, cfg, "", nil, &out); err == nil {
		t.Fatal("expected error")
	}
	if !fv.revoked {
		t.Error("token not revoked after cancellation")
	}
	if out.Len() != 0 {
		t.Errorf("wrote output despite cancellation: %s", out.String())
	}
}

func TestRequestHeaders(t *testing.T) {
	t.Parallel()
	var gotNS, gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/custom/login" {
			gotNS = r.Header.Get("X-Vault-Namespace")
			writeJSON(w, 200, map[string]any{"auth": map[string]any{"client_token": "tok"}})
			return
		}
		gotToken = r.Header.Get("X-Vault-Token")
		writeJSON(w, 404, map[string]any{})
	}))
	t.Cleanup(srv.Close)
	cfg := &Config{Address: srv.URL + "/", Namespace: "team-a", Timeout: "5s"}
	c, err := newClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.login(t.Context(), "/custom/", "r", "s"); err != nil {
		t.Fatal(err)
	}
	if gotNS != "team-a" {
		t.Errorf("namespace header = %q", gotNS)
	}
	if err = c.do(t.Context(), http.MethodGet, "anything", nil, nil); !errors.Is(err, errNotFound) {
		t.Errorf("err = %v, want errNotFound", err)
	}
	if gotToken != "tok" {
		t.Errorf("token header = %q", gotToken)
	}
}

func TestLoadConfig(t *testing.T) {
	t.Parallel()
	t.Run("defaults", func(t *testing.T) {
		t.Parallel()
		p := writeConfig(
			t,
			map[string]any{"address": "http://x", "role_id": "r", "secret_id": "s", "paths": []string{"secret"}},
		)
		cfg, err := loadConfig(p)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.AppRoleMount != "approle" || cfg.Timeout != "30s" {
			t.Errorf("defaults not applied: %+v", cfg)
		}
	})

	t.Run("unknown field", func(t *testing.T) {
		t.Parallel()
		cfg := map[string]any{"address": "http://x", "role_id": "r", "secret_id": "s", "namspace": "x"}
		_, err := loadConfig(writeConfig(t, cfg))
		if err == nil || !strings.Contains(err.Error(), `unknown field "namspace"`) {
			t.Errorf("err = %v, want unknown field error", err)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		t.Parallel()
		p := filepath.Join(t.TempDir(), "c.json")
		if err := os.WriteFile(p, []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(p); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		if _, err := loadConfig(filepath.Join(t.TempDir(), "nope.json")); err == nil {
			t.Error("expected error")
		}
	})
}

func clearCredentialEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"VAULT_ROLE_ID", "VAULT_SECRET_ID", "VAULT_SECRET_ID_FILE"} {
		t.Setenv(k, "")
	}
}

// writeSecret writes content to a temporary file and returns its path.
func writeSecret(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret-id")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

//nolint:paralleltest // sets environment variables, which parallel tests must not do
func TestLoadConfigEnv(t *testing.T) {
	t.Run("env overrides credentials", func(t *testing.T) {
		clearCredentialEnv(t)
		t.Setenv("VAULT_ROLE_ID", "env-role")
		t.Setenv("VAULT_SECRET_ID", "env-secret")
		p := writeConfig(t, map[string]any{"address": "http://x", "role_id": "file-role", "paths": []string{"secret"}})
		cfg, err := loadConfig(p)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.RoleID != "env-role" || cfg.SecretID != "env-secret" {
			t.Errorf("env not applied: %+v", cfg)
		}
	})

	t.Run("secret_id_file", func(t *testing.T) {
		clearCredentialEnv(t)
		p := writeConfig(
			t,
			map[string]any{"address": "http://x", "role_id": "r", "secret_id_file": writeSecret(t, "from-file\n")},
		)
		cfg, err := loadConfig(p)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.SecretID != "from-file" {
			t.Errorf("secret_id = %q, want trimmed file content", cfg.SecretID)
		}
	})

	t.Run("VAULT_SECRET_ID_FILE overrides config", func(t *testing.T) {
		clearCredentialEnv(t)
		t.Setenv("VAULT_SECRET_ID_FILE", writeSecret(t, "env-file"))
		p := writeConfig(t, map[string]any{"address": "http://x", "role_id": "r", "secret_id": "in-config"})
		cfg, err := loadConfig(p)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.SecretID != "env-file" {
			t.Errorf("secret_id = %q, want env-file", cfg.SecretID)
		}
	})

	t.Run("VAULT_SECRET_ID overrides secret_id_file", func(t *testing.T) {
		clearCredentialEnv(t)
		t.Setenv("VAULT_SECRET_ID", "env-value")
		p := writeConfig(t, map[string]any{"address": "http://x", "role_id": "r", "secret_id_file": "/nonexistent"})
		cfg, err := loadConfig(p)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.SecretID != "env-value" {
			t.Errorf("secret_id = %q, want env-value", cfg.SecretID)
		}
	})

	t.Run("both env variables", func(t *testing.T) {
		clearCredentialEnv(t)
		t.Setenv("VAULT_SECRET_ID", "a")
		t.Setenv("VAULT_SECRET_ID_FILE", writeSecret(t, "b"))
		_, err := loadConfig(writeConfig(t, map[string]any{"address": "http://x", "role_id": "r"}))
		if err == nil || !strings.Contains(err.Error(), "only one of VAULT_SECRET_ID and VAULT_SECRET_ID_FILE") {
			t.Errorf("err = %v", err)
		}
	})

	errCases := []struct {
		name string
		cfg  map[string]any
		want string
	}{
		{"missing address", map[string]any{"role_id": "r", "secret_id": "s", "paths": []string{"a"}}, "address"},
		{
			"secret_id and secret_id_file",
			map[string]any{"address": "http://x", "role_id": "r", "secret_id": "s", "secret_id_file": "/nonexistent"},
			"only one of secret_id and secret_id_file",
		},
		{
			"missing secret_id_file",
			map[string]any{"address": "http://x", "role_id": "r", "secret_id_file": "/nonexistent"},
			"secret_id_file: open /nonexistent",
		},
		{
			"empty secret_id_file",
			map[string]any{"address": "http://x", "role_id": "r", "secret_id_file": "EMPTY"},
			"is empty",
		},
		{
			"missing secret_id",
			map[string]any{"address": "http://x", "role_id": "r", "paths": []string{"a"}},
			"secret_id",
		},
	}
	for _, tt := range errCases {
		t.Run(tt.name, func(t *testing.T) {
			clearCredentialEnv(t)
			if tt.cfg["secret_id_file"] == "EMPTY" {
				tt.cfg["secret_id_file"] = writeSecret(t, " \n")
			}
			_, err := loadConfig(writeConfig(t, tt.cfg))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want mention of %q", err, tt.want)
			}
		})
	}
}

func TestNewClient(t *testing.T) {
	t.Parallel()
	if _, err := newClient(&Config{Address: "http://x", Timeout: "soon"}); err == nil {
		t.Error("expected error for bad timeout")
	}
}

func TestEscapePath(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"secret/app/db":     "secret/app/db",
		"secret/odd name/x": "secret/odd%20name/x",
		"secret/a?b#c":      "secret/a%3Fb%23c",
		"secret/dir/":       "secret/dir/",
	}
	for in, want := range tests {
		if got := escapePath(in); got != want {
			t.Errorf("escapePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// oddNames are key names Vault accepts that need escaping or are easy to mangle.
// Vault itself rejects ".", ".." and control characters.
func oddNames() []string {
	return []string{
		"100%", "a+b", "semi;colon", `back\slash`, "dot.s", "sp ace ", "comma,x",
		"*star", "a:b", "~tilde", "=eq", "&amp", "emoji😀", "ü?#x",
	}
}

// normJSON round-trips v through JSON so Go literals and decoded values compare equal.
func normJSON(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err = decodeJSON(bytes.NewReader(b), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func emptyFakeVault() *fakeVault {
	fv := newFakeVault()
	fv.secrets = map[string]map[string]any{}
	fv.meta = map[string]*metadata{}
	fv.deleted = map[string]bool{}
	return fv
}

// backupAndRestore backs up paths from src, restores the result into an empty fake Vault
// and returns that Vault together with the raw backup.
func backupAndRestore(t *testing.T, src *fakeVault, paths ...string) (*fakeVault, string) {
	t.Helper()
	srv := httptest.NewServer(src)
	t.Cleanup(srv.Close)
	cfg := writeConfig(t, map[string]any{
		"address": srv.URL, "role_id": testRoleID, "secret_id": testSecretID, "paths": paths,
	})
	var out bytes.Buffer
	if err := run(t.Context(), cfg, "", nil, &out); err != nil {
		t.Fatal(err)
	}
	dst := emptyFakeVault()
	if err := restoreFakeVault(t, dst, out.String()); err != nil {
		t.Fatal(err)
	}
	return dst, out.String()
}

func TestOddKeyNames(t *testing.T) {
	t.Parallel()
	src := emptyFakeVault()
	for i, n := range oddNames() {
		src.secrets["secret/odd/"+n] = map[string]any{"i": float64(i)}
		src.secrets["kv1/odd/"+n] = map[string]any{"i": float64(i)}
		src.secrets["secret/dir "+n+"/leaf"] = map[string]any{"i": float64(i)}
	}
	dst, _ := backupAndRestore(t, src, "secret", "kv1")
	if got, want := normJSON(t, dst.secrets), normJSON(t, src.secrets); !reflect.DeepEqual(got, want) {
		t.Errorf("round trip mismatch:\ngot  %v\nwant %v", got, want)
	}
}

func TestOddValues(t *testing.T) {
	t.Parallel()
	src := emptyFakeVault()
	values := map[string]any{
		"null":    nil,
		"html":    "<b>&amp;</b>",
		"unicode": "ü😀 ",
		"bool":    false,
		"float":   json.Number("1.5"),
		"neg":     json.Number("-0"),
		"big":     json.Number("9007199254740993"),
		"emptyO":  map[string]any{},
		"emptyA":  []any{},
		"deep":    map[string]any{"a": []any{map[string]any{"b": []any{nil, true, "x"}}}},
		"long":    strings.Repeat("x", 1<<20),
	}
	src.secrets["secret/values"] = values
	src.secrets["kv1/values"] = values
	src.secrets["secret/empty"] = map[string]any{} // KV v2 accepts empty data, v1 does not
	dst, raw := backupAndRestore(t, src, "secret", "kv1")
	if got, want := normJSON(t, dst.secrets), normJSON(t, src.secrets); !reflect.DeepEqual(got, want) {
		t.Errorf("round trip mismatch for %v", want)
	}
	if !strings.Contains(raw, `"<b>&amp;</b>"`) {
		t.Error("HTML characters were escaped in the backup")
	}
}

func TestExportSecretAndDirectory(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		path       string
		forbidSelf bool
		want       []string
	}{
		{
			"path covers secret and directory",
			"secret/app",
			false,
			[]string{"secret/app", "secret/app/api", "secret/app/db"},
		},
		{"trailing slash is directory only", "secret/app/", false, []string{"secret/app/api", "secret/app/db"}},
		{"unreadable secret is skipped", "secret/app", true, []string{"secret/app/api", "secret/app/db"}},
		{
			"whole mount",
			"secret",
			false,
			[]string{"secret/app", "secret/app/api", "secret/app/db", "secret/odd name/x", "secret/top"},
		},
		{"v1 path covers both", "kv1/team-a", false, []string{"kv1/team-a", "kv1/team-a/one"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fv := newFakeVault()
			fv.secrets["secret/app"] = map[string]any{"self": "1"}
			fv.secrets["kv1/team-a"] = map[string]any{"self": "1"}
			if tt.forbidSelf {
				fv.forbidden["secret/data/app"] = true
			}
			got, err := runBackup(t, fv, tt.path)
			if err != nil {
				t.Fatal(err)
			}
			if keys := slices.Sorted(maps.Keys(got)); !reflect.DeepEqual(keys, tt.want) {
				t.Errorf("keys = %q, want %q", keys, tt.want)
			}
		})
	}
}

func TestRestoreTwiceAddsNoVersions(t *testing.T) {
	t.Parallel()
	fv := emptyFakeVault()
	fv.secrets["secret/gone"] = map[string]any{"x": "1"}
	fv.deleted["secret/gone"] = true // same data, but the current version is deleted
	backup := `{
		"secret/a": {"data": {"n": 1, "x": {"y": [true, null]}},
			"metadata": {"max_versions": 3, "delete_version_after": "0s", "custom_metadata": {"k": "v"}}},
		"secret/b": {"data": {"k": "v"}, "metadata": {"delete_version_after": "0s", "custom_metadata": null}},
		"secret/gone": {"data": {"x": "1"}},
		"kv1/c": {"data": {"k": "v"}}
	}`
	if err := restoreFakeVault(t, fv, backup); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"secret/a": 1, "secret/b": 1, "secret/gone": 2}
	if !reflect.DeepEqual(fv.versions, want) {
		t.Fatalf("versions after first restore = %v, want %v", fv.versions, want)
	}

	fv.requests = nil
	if err := restoreFakeVault(t, fv, backup); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fv.versions, want) {
		t.Errorf("versions after second restore = %v, want %v", fv.versions, want)
	}
	for _, r := range fv.requests {
		if strings.HasPrefix(r, "POST secret/") {
			t.Errorf("second restore wrote %s", r)
		}
	}
}

// dropFirstResponse lets the first request for method and path through to next, then
// drops the connection instead of answering, as if the response was lost on the way back.
func dropFirstResponse(method, path string, next http.Handler) http.Handler {
	var mu sync.Mutex
	dropped := false
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		drop := !dropped && r.Method == method && r.URL.Path == "/v1/"+path
		dropped = dropped || drop
		mu.Unlock()
		if !drop {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(httptest.NewRecorder(), r)
		dropConnection(w)
	})
}

func TestRestoreRetriedWriteThatLanded(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, path, backup string
		wantVersion        int
	}{
		{"new secret", "secret/data/fresh", `{"secret/fresh": {"data": {"a": "b"}}}`, 1},
		{
			"existing secret with cas_required",
			"secret/data/app/db",
			`{"secret/app/db": {"data": {"a": "b"}, "metadata": {"cas_required": true}}}`,
			2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fv := newFakeVault()
			srv := httptest.NewServer(dropFirstResponse("POST", tt.path, fv))
			t.Cleanup(srv.Close)
			cfg := writeConfig(t, map[string]any{"address": srv.URL, "role_id": testRoleID, "secret_id": testSecretID})
			if err := run(t.Context(), cfg, "-", strings.NewReader(tt.backup), nil); err != nil {
				t.Fatal(err)
			}
			p := strings.Replace(tt.path, "/data/", "/", 1)
			if fv.versions[p] != tt.wantVersion {
				t.Errorf("version = %d, want %d (written once)", fv.versions[p], tt.wantVersion)
			}
			if !fv.metadataFor(p).CASRequired && strings.Contains(tt.backup, "cas_required") {
				t.Error("metadata was not written after the recovered data write")
			}
		})
	}
}

func TestSameJSON(t *testing.T) {
	t.Parallel()
	n := func(s string) json.Number { return json.Number(s) }
	tests := []struct {
		name string
		a, b any
		want bool
	}{
		{
			"equal maps",
			map[string]any{"a": "x", "b": []any{true, nil}},
			map[string]any{"a": "x", "b": []any{true, nil}},
			true,
		},
		{
			"number formatting",
			map[string]any{"a": n("1.0"), "b": n("1e3")},
			map[string]any{"a": n("1"), "b": n("1000")},
			true,
		},
		{"different numbers", n("1"), n("2"), false},
		{"number vs string", n("1"), "1", false},
		{"missing key", map[string]any{"a": nil}, map[string]any{"b": nil}, false},
		{"extra key", map[string]any{"a": "x"}, map[string]any{"a": "x", "b": "y"}, false},
		{"array order", []any{"a", "b"}, []any{"b", "a"}, false},
		{"array length", []any{"a"}, []any{"a", "a"}, false},
		{"null vs missing", map[string]any{"a": nil}, map[string]any{}, false},
		{"empty map vs empty array", map[string]any{}, []any{}, false},
		{"bool", true, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sameJSON(tt.a, tt.b); got != tt.want {
				t.Errorf("sameJSON = %v, want %v", got, tt.want)
			}
		})
	}
}
