//go:build integration

// Integration tests against a real Vault dev server in Docker.
//
//	go test -tags integration -count=1 ./...
//
// Set VAULT_IMAGE to test against another image (e.g. openbao/openbao).

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

const rootToken = "root"

type vaultContainer struct {
	t    *testing.T
	name string
	addr string
}

func startVault(t *testing.T) *vaultContainer {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	image := os.Getenv("VAULT_IMAGE")
	if image == "" {
		image = "hashicorp/vault:1.18"
	}

	name := fmt.Sprintf("kibotos-it-%d", time.Now().UnixNano())
	out, err := exec.CommandContext(t.Context(), "docker", "run", "-d", "--rm", "--name", name,
		"-p", "127.0.0.1::8200",
		"-e", "VAULT_DEV_ROOT_TOKEN_ID="+rootToken,
		"-e", "BAO_DEV_ROOT_TOKEN_ID="+rootToken,
		"-e", "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
		"-e", "BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
		image).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { // t.Context is already canceled when cleanups run
		_ = exec.CommandContext(context.Background(), "docker", "rm", "-f", name).Run()
	})

	out, err = exec.CommandContext(t.Context(), "docker", "port", name, "8200/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	hostPort := strings.TrimSpace(strings.Split(string(out), "\n")[0])
	v := &vaultContainer{t: t, name: name, addr: "http://" + hostPort}

	deadline := time.Now().Add(30 * time.Second)
	for !healthy(t, v.addr) {
		if time.Now().After(deadline) {
			logs, _ := exec.CommandContext(t.Context(), "docker", "logs", name).CombinedOutput()
			t.Fatalf("vault did not become healthy\n%s", logs)
		}
		time.Sleep(200 * time.Millisecond)
	}
	return v
}

// healthy reports whether the Vault at addr answers its health check as active.
func healthy(t *testing.T, addr string) bool {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, addr+"/v1/sys/health", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// field returns the value at path in a decoded Vault response, failing the test if
// it is missing or not a T.
func field[T any](t *testing.T, m map[string]any, path ...string) T {
	t.Helper()
	var cur any = m
	for _, k := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("no object at %q in %v", k, m)
		}
		cur = obj[k]
	}
	val, ok := cur.(T)
	if !ok {
		t.Fatalf("%q is %T, want %T, in %v", path, cur, val, m)
	}
	return val
}

// api calls the Vault HTTP API with the root token and returns the decoded response.
func (v *vaultContainer) api(method, path string, body any) map[string]any {
	v.t.Helper()
	var b []byte
	if body != nil {
		var err error
		if b, err = json.Marshal(body); err != nil {
			v.t.Fatal(err)
		}
	}
	req, err := http.NewRequestWithContext(v.t.Context(), method, v.addr+"/v1/"+path, bytes.NewReader(b))
	if err != nil {
		v.t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", rootToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		v.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 300 {
		var e map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&e)
		v.t.Fatalf("%s %s: %s %v", method, path, resp.Status, e)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func (v *vaultContainer) putV2(mount, path string, data map[string]any) {
	v.api("POST", mount+"/data/"+escapePath(path), map[string]any{"data": data})
}

func (v *vaultContainer) putV1(mount, path string, data map[string]any) {
	v.api("POST", mount+"/"+escapePath(path), data)
}

// approle creates an AppRole with the given policy and returns its role_id and secret_id.
func (v *vaultContainer) approle(name, policy string) (string, string) {
	v.api("PUT", "sys/policies/acl/"+name, map[string]any{"policy": policy})
	v.api("POST", "auth/approle/role/"+name, map[string]any{"token_policies": []string{name}, "token_ttl": "5m"})
	roleID := field[string](v.t, v.api("GET", "auth/approle/role/"+name+"/role-id", nil), "data", "role_id")
	secretID := field[string](v.t, v.api("POST", "auth/approle/role/"+name+"/secret-id", nil), "data", "secret_id")
	return roleID, secretID
}

func (v *vaultContainer) backup(roleID, secretID string, paths ...string) (map[string]secret, error) {
	v.t.Helper()
	cfg := writeConfig(v.t, map[string]any{
		"address": v.addr, "role_id": roleID, "secret_id": secretID, "paths": paths,
	})
	var out bytes.Buffer
	if err := run(v.t.Context(), cfg, "", nil, &out); err != nil {
		return nil, err
	}
	var got map[string]secret
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		v.t.Fatalf("invalid JSON output: %v\n%s", err, out.String())
	}
	return got, nil
}

func dataOf(backup map[string]secret) map[string]map[string]any {
	out := map[string]map[string]any{}
	for p, s := range backup {
		out[p] = s.Data
	}
	return out
}

//nolint:paralleltest // subtests share one Vault and check global state such as the token count
func TestIntegration(t *testing.T) {
	v := startVault(t)

	v.api("POST", "sys/mounts/kv1", map[string]any{"type": "kv", "options": map[string]string{"version": "1"}})
	v.api("POST", "sys/mounts/team/kv", map[string]any{"type": "kv", "options": map[string]string{"version": "2"}})
	v.api("POST", "sys/auth/approle", map[string]any{"type": "approle"})

	v.putV2("secret", "app/db", map[string]any{"user": "admin", "pass": "old"})
	v.putV2("secret", "app/db", map[string]any{"user": "admin", "pass": "new"}) // version 2
	v.putV2("secret", "app/api", map[string]any{"token": "abc", "nested": map[string]any{"a": []any{1.0, "two"}}})
	v.putV2("secret", "a/b/c/d/deep", map[string]any{"x": "y"})
	v.putV2("secret", "odd name/ü?#x", map[string]any{"k": "v"})
	v.putV2("secret", "gone", map[string]any{"x": "1"})
	v.api("DELETE", "secret/data/gone", nil) // soft delete
	v.putV2("team/kv", "svc", map[string]any{"s": "t"})
	v.putV1("kv1", "team-a/one", map[string]any{"k": "v1"})
	v.putV1("kv1", "team-b/two", map[string]any{"k": "v2"})
	v.api("POST", "secret/metadata/app/db", map[string]any{
		"max_versions":         7,
		"cas_required":         true,
		"delete_version_after": "2h",
		"custom_metadata":      map[string]string{"owner": "team-a"},
	})

	fullRole, fullSecret := v.approle("full", `
path "secret/metadata"   { capabilities = ["list"] }
path "secret/metadata/*" { capabilities = ["read", "list"] }
path "secret/data/*"     { capabilities = ["read"] }
path "team/kv/metadata"   { capabilities = ["list"] }
path "team/kv/metadata/*" { capabilities = ["read", "list"] }
path "team/kv/data/*"     { capabilities = ["read"] }
path "kv1"   { capabilities = ["list"] }
path "kv1/*" { capabilities = ["read", "list"] }
`)

	t.Run("whole kv2 mount", func(t *testing.T) {
		got, err := v.backup(fullRole, fullSecret, "secret")
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]map[string]any{
			"secret/app/db":        {"user": "admin", "pass": "new"},
			"secret/app/api":       {"token": "abc", "nested": map[string]any{"a": []any{1.0, "two"}}},
			"secret/a/b/c/d/deep":  {"x": "y"},
			"secret/odd name/ü?#x": {"k": "v"},
		}
		if !reflect.DeepEqual(dataOf(got), want) {
			t.Errorf("got  %v\nwant %v", dataOf(got), want)
		}
		wantMeta := metadata{
			MaxVersions:        7,
			CASRequired:        true,
			DeleteVersionAfter: "2h0m0s",
			CustomMetadata:     map[string]string{"owner": "team-a"},
		}
		if md := got["secret/app/db"].Metadata; md == nil || !reflect.DeepEqual(*md, wantMeta) {
			t.Errorf("metadata = %+v, want %+v", md, wantMeta)
		}
		if md := got["secret/app/api"].Metadata; md == nil ||
			!reflect.DeepEqual(*md, metadata{DeleteVersionAfter: "0s"}) {
			t.Errorf("default metadata = %+v", md)
		}
	})

	t.Run("whole kv1 mount", func(t *testing.T) {
		got, err := v.backup(fullRole, fullSecret, "kv1")
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]map[string]any{
			"kv1/team-a/one": {"k": "v1"},
			"kv1/team-b/two": {"k": "v2"},
		}
		for p, s := range got {
			if s.Metadata != nil {
				t.Errorf("%s: v1 secret has metadata", p)
			}
		}
		if !reflect.DeepEqual(dataOf(got), want) {
			t.Errorf("got  %v\nwant %v", got, want)
		}
	})

	t.Run("multi-segment mount, subdir and single secret", func(t *testing.T) {
		got, err := v.backup(fullRole, fullSecret, "team/kv", "secret/a/b", "kv1/team-a/one")
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]map[string]any{
			"team/kv/svc":         {"s": "t"},
			"secret/a/b/c/d/deep": {"x": "y"},
			"kv1/team-a/one":      {"k": "v1"},
		}
		if !reflect.DeepEqual(dataOf(got), want) {
			t.Errorf("got  %v\nwant %v", got, want)
		}
	})

	t.Run("token is revoked", func(t *testing.T) {
		before := len(field[[]any](t, v.api("LIST", "auth/token/accessors", nil), "data", "keys"))
		if _, err := v.backup(fullRole, fullSecret, "secret/app"); err != nil {
			t.Fatal(err)
		}
		after := len(field[[]any](t, v.api("LIST", "auth/token/accessors", nil), "data", "keys"))
		if after != before {
			t.Errorf("token count went from %d to %d; backup token not revoked", before, after)
		}
	})

	t.Run("insufficient permissions fail the backup", func(t *testing.T) {
		role, secret := v.approle("partial", `
path "secret/metadata"   { capabilities = ["list"] }
path "secret/metadata/*" { capabilities = ["list"] }
path "secret/data/app/*" { capabilities = ["read"] }
`)
		_, err := v.backup(role, secret, "secret")
		if err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("err = %v, want 403", err)
		}
	})

	t.Run("bad credentials", func(t *testing.T) {
		_, err := v.backup(fullRole, "00000000-0000-0000-0000-000000000000", "secret")
		if err == nil || !strings.Contains(err.Error(), "approle login") {
			t.Fatalf("err = %v, want approle login error", err)
		}
	})

	t.Run("token is renewed past its TTL", func(t *testing.T) {
		role, secret := v.approle("short", `path "secret/metadata/*" { capabilities = ["read", "list"] }`)
		v.api("POST", "auth/approle/role/short", map[string]any{"token_ttl": "4s", "token_max_ttl": "1m"})
		c, err := newClient(&Config{Address: v.addr, Timeout: "5s"})
		if err != nil {
			t.Fatal(err)
		}
		if err = c.login(t.Context(), "approle", role, secret); err != nil {
			t.Fatal(err)
		}
		defer c.revoke(t.Context())
		for range 3 { // 6s in total, well past the 4s TTL
			time.Sleep(2 * time.Second)
			if _, err = c.readMetadata(t.Context(), "secret/", "app/db"); err != nil {
				t.Fatalf("token expired despite renewal: %v", err)
			}
		}
	})

	t.Run("backup, wipe, restore round trip", func(t *testing.T) {
		mounts := map[string]string{"rt-v2": "2", "rt-v1": "1"}
		for m, ver := range mounts {
			v.api("POST", "sys/mounts/"+m, map[string]any{"type": "kv", "options": map[string]string{"version": ver}})
		}
		v.putV2("rt-v2", "app/db", map[string]any{"user": "admin", "pass": "s3 cr=t"})
		v.putV2("rt-v2", "app/db", map[string]any{"user": "admin", "pass": "newer"})
		v.putV2("rt-v2", "odd name/ü?#x", map[string]any{"nested": map[string]any{"a": []any{1, "two"}}, "b": true})
		// KV v2 itself rounds integers above 2^53, so precision can only be checked on v1.
		v.putV1("rt-v1", "team/one", map[string]any{"k": "v", "big": json.Number("9007199254740993")})
		v.api("POST", "rt-v2/metadata/app/db", map[string]any{
			"max_versions":         4,
			"cas_required":         true,
			"delete_version_after": "90m",
			"custom_metadata":      map[string]string{"owner": "x", "env": "prod"},
		})
		v.api("POST", "rt-v2/metadata/odd name/ü?#x", map[string]any{"custom_metadata": map[string]string{"k": "v"}})

		role, secret := v.approle("restore", `
path "rt-v2/metadata"   { capabilities = ["list"] }
path "rt-v2/metadata/*" { capabilities = ["read", "list", "create", "update"] }
path "rt-v2/data/*"     { capabilities = ["read", "create", "update"] }
path "rt-v1"   { capabilities = ["list"] }
path "rt-v1/*" { capabilities = ["read", "list", "create", "update"] }
`)
		cfg := writeConfig(t, map[string]any{
			"address": v.addr, "role_id": role, "secret_id": secret, "paths": []string{"rt-v2", "rt-v1"},
		})
		var first bytes.Buffer
		if err := run(t.Context(), cfg, "", nil, &first); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(first.String(), "9007199254740993") {
			t.Errorf("large integer lost precision:\n%s", first.String())
		}

		// Wipe by re-creating the mounts.
		for m, ver := range mounts {
			v.api("DELETE", "sys/mounts/"+m, nil)
			v.api("POST", "sys/mounts/"+m, map[string]any{"type": "kv", "options": map[string]string{"version": ver}})
		}
		if got, err := v.backup(role, secret, "rt-v2", "rt-v1"); err != nil || len(got) != 0 {
			t.Fatalf("mounts not empty after wipe: %v %v", got, err)
		}

		if err := run(t.Context(), cfg, "-", bytes.NewReader(first.Bytes()), nil); err != nil {
			t.Fatal(err)
		}
		var second bytes.Buffer
		if err := run(t.Context(), cfg, "", nil, &second); err != nil {
			t.Fatal(err)
		}
		if first.String() != second.String() {
			t.Errorf("round trip mismatch:\nbefore %s\nafter  %s", first.String(), second.String())
		}

		// Restoring over existing secrets must work despite cas_required and must reset changed metadata.
		v.api(
			"POST",
			"rt-v2/metadata/odd name/ü?#x",
			map[string]any{"custom_metadata": map[string]string{"extra": "1"}, "max_versions": 9},
		)
		if err := run(t.Context(), cfg, "-", bytes.NewReader(first.Bytes()), nil); err != nil {
			t.Fatal(err)
		}
		var third bytes.Buffer
		if err := run(t.Context(), cfg, "", nil, &third); err != nil {
			t.Fatal(err)
		}
		if first.String() != third.String() {
			t.Errorf("restore over existing mismatch:\nbefore %s\nafter  %s", first.String(), third.String())
		}
	})
	t.Run("edge cases against real Vault", func(t *testing.T) {
		v.api("POST", "sys/mounts/edge-v2", map[string]any{"type": "kv", "options": map[string]string{"version": "2"}})
		v.api("POST", "sys/mounts/edge-v1", map[string]any{"type": "kv", "options": map[string]string{"version": "1"}})
		role, secretID := v.approle("edge", `
path "edge-v2/metadata"   { capabilities = ["list"] }
path "edge-v2/metadata/*" { capabilities = ["read", "list", "create", "update"] }
path "edge-v2/data/*"     { capabilities = ["read", "create", "update"] }
path "edge-v1"   { capabilities = ["list"] }
path "edge-v1/*" { capabilities = ["read", "list", "create", "update"] }
`)
		for _, n := range oddNames() {
			v.putV2("edge-v2", "odd/"+n, map[string]any{"name": n})
			v.putV1("edge-v1", "odd/"+n, map[string]any{"name": n})
		}
		values := map[string]any{
			"null":    nil,
			"html":    "<b>&amp;</b>",
			"unicode": "ü😀",
			"bool":    false,
			"float":   1.5,
			"emptyO":  map[string]any{},
			"emptyA":  []any{},
			"deep":    map[string]any{"a": []any{map[string]any{"b": []any{nil, true}}}},
		}
		v.putV2("edge-v2", "values", values)
		v.putV1("edge-v1", "values", values)
		v.putV2("edge-v2", "empty", map[string]any{}) // KV v1 rejects empty data
		v.putV2("edge-v2", "both", map[string]any{"self": "1"})
		v.putV2("edge-v2", "both/child", map[string]any{"c": "1"})
		v.putV1("edge-v1", "both", map[string]any{"self": "1"})
		v.putV1("edge-v1", "both/child", map[string]any{"c": "1"})

		for path, want := range map[string][]string{
			"edge-v2/both":  {"edge-v2/both", "edge-v2/both/child"},
			"edge-v2/both/": {"edge-v2/both/child"},
			"edge-v1/both":  {"edge-v1/both", "edge-v1/both/child"},
		} {
			got, err := v.backup(role, secretID, path)
			if err != nil {
				t.Fatal(err)
			}
			if keys := slices.Sorted(maps.Keys(got)); !reflect.DeepEqual(keys, want) {
				t.Errorf("backup %q = %q, want %q", path, keys, want)
			}
		}

		cfg := writeConfig(t, map[string]any{
			"address": v.addr, "role_id": role, "secret_id": secretID, "paths": []string{"edge-v2", "edge-v1"},
		})
		var first bytes.Buffer
		if err := run(t.Context(), cfg, "", nil, &first); err != nil {
			t.Fatal(err)
		}
		var got map[string]secret
		if err := decodeJSON(bytes.NewReader(first.Bytes()), &got); err != nil {
			t.Fatal(err)
		}
		for _, n := range oddNames() {
			for _, m := range []string{"edge-v2/odd/", "edge-v1/odd/"} {
				if got[m+n].Data["name"] != n {
					t.Errorf("%s%s: data = %v", m, n, got[m+n].Data)
				}
			}
		}
		if s, ok := got["edge-v2/empty"]; !ok || s.Data == nil || len(s.Data) != 0 {
			t.Errorf("empty v2 secret = %+v, %v", s, ok)
		}
		if !strings.Contains(first.String(), `"<b>&amp;</b>"`) {
			t.Error("HTML characters were escaped in the backup")
		}

		// Check versions through kibotos's own client with the restore role, not as root.
		c, err := newClient(&Config{Address: v.addr, Timeout: "5s"})
		if err != nil {
			t.Fatal(err)
		}
		if err = c.login(t.Context(), "approle", role, secretID); err != nil {
			t.Fatal(err)
		}
		defer c.revoke(t.Context())
		version := func(rel string) int {
			t.Helper()
			md, mdErr := c.readMetadata(t.Context(), "edge-v2/", rel)
			if mdErr != nil {
				t.Fatal(mdErr)
			}
			return md.CurrentVersion
		}
		versions := func() map[string]int {
			out := map[string]int{}
			for p := range got {
				if rel, ok := strings.CutPrefix(p, "edge-v2/"); ok {
					out[p] = version(rel)
				}
			}
			return out
		}

		// Restoring over identical secrets must not add versions.
		before := versions()
		if err = run(t.Context(), cfg, "-", bytes.NewReader(first.Bytes()), nil); err != nil {
			t.Fatal(err)
		}
		if after := versions(); !reflect.DeepEqual(after, before) {
			t.Errorf("restore over identical secrets added versions:\nbefore %v\nafter  %v", before, after)
		}

		// Wipe, restore through a proxy that loses the response to one write, and compare.
		for _, m := range []string{"edge-v2", "edge-v1"} {
			ver := map[string]string{"edge-v2": "2", "edge-v1": "1"}[m]
			v.api("DELETE", "sys/mounts/"+m, nil)
			v.api("POST", "sys/mounts/"+m, map[string]any{"type": "kv", "options": map[string]string{"version": ver}})
		}
		target, err := url.Parse(v.addr)
		if err != nil {
			t.Fatal(err)
		}
		proxy := httptest.NewServer(
			dropFirstResponse("POST", "edge-v2/data/values", httputil.NewSingleHostReverseProxy(target)),
		)
		t.Cleanup(proxy.Close)
		proxyCfg := writeConfig(t, map[string]any{"address": proxy.URL, "role_id": role, "secret_id": secretID})
		if err = run(t.Context(), proxyCfg, "-", bytes.NewReader(first.Bytes()), nil); err != nil {
			t.Fatalf("restore with a lost write response: %v", err)
		}
		if ver := version("values"); ver != 1 {
			t.Errorf("edge-v2/values version = %d, want 1 (written once)", ver)
		}
		var second bytes.Buffer
		if err = run(t.Context(), cfg, "", nil, &second); err != nil {
			t.Fatal(err)
		}
		if first.String() != second.String() {
			t.Errorf("round trip mismatch:\nbefore %s\nafter  %s", first.String(), second.String())
		}
	})
}
