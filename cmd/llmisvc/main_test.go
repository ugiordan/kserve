/*
Copyright 2026 The KServe Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/tls"
	"reflect"
	"testing"

	"k8s.io/client-go/rest"
)

// fakeResolve records the arguments it was called with and returns canned
// policy-derived TLS options, standing in for the cluster profile resolution.
func fakeResolve(tlsOpts []func(*tls.Config)) func(context.Context, *rest.Config, string, string) ([]func(*tls.Config), error) {
	return func(_ context.Context, _ *rest.Config, minVer, ciphers string) ([]func(*tls.Config), error) {
		if minVer != "" || ciphers != "" {
			// Explicit flags bypass the cluster policy in the real resolver.
			return []func(*tls.Config){
				func(c *tls.Config) {
					c.MinVersion = tls.VersionTLS12
					c.NextProtos = []string{"h2", "http/1.1"}
				},
			}, nil
		}
		out := make([]func(*tls.Config), len(tlsOpts))
		copy(out, tlsOpts)
		return out, nil
	}
}

func applyTLSOpts(t *testing.T, opts []func(*tls.Config)) *tls.Config {
	t.Helper()
	cfg := &tls.Config{}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

func TestSelectTLSOpts_ExplicitHTTP2FalseOverridesOnlyALPN(t *testing.T) {
	tests := []struct {
		name string
		// policy simulates the resolved cluster policy TLS options.
		policy []func(*tls.Config)
	}{
		{
			name: "strict modern policy keeps TLS 1.3",
			policy: []func(*tls.Config){
				func(c *tls.Config) {
					c.MinVersion = tls.VersionTLS13
					c.NextProtos = []string{"h2", "http/1.1"}
				},
			},
		},
		{
			name: "intermediate policy keeps min version and cipher suites",
			policy: []func(*tls.Config){
				func(c *tls.Config) {
					c.MinVersion = tls.VersionTLS12
					c.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
					c.NextProtos = []string{"h2", "http/1.1"}
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := Options{enableHTTP2: false}
			tlsOpts, err := selectTLSOpts(context.Background(), nil, opts, true, fakeResolve(tc.policy))
			if err != nil {
				t.Fatalf("selectTLSOpts() error = %v", err)
			}
			cfg := applyTLSOpts(t, tlsOpts)
			if cfg.MinVersion == 0 {
				t.Fatal("expected policy-derived MinVersion to be preserved")
			}
			if len(cfg.CipherSuites) == 0 && tc.name == "intermediate policy keeps min version and cipher suites" {
				t.Fatal("expected policy-derived cipher suites to be preserved")
			}
			if !reflect.DeepEqual(cfg.NextProtos, []string{"http/1.1"}) {
				t.Fatalf("expected NextProtos [http/1.1], got %v", cfg.NextProtos)
			}
		})
	}
}

func TestSelectTLSOpts_ExplicitHTTP2TrueKeepsPolicyALPN(t *testing.T) {
	policy := []func(*tls.Config){
		func(c *tls.Config) {
			c.MinVersion = tls.VersionTLS13
			c.NextProtos = []string{"h2", "http/1.1"}
		},
	}
	opts := Options{enableHTTP2: true}
	tlsOpts, err := selectTLSOpts(context.Background(), nil, opts, true, fakeResolve(policy))
	if err != nil {
		t.Fatalf("selectTLSOpts() error = %v", err)
	}
	cfg := applyTLSOpts(t, tlsOpts)
	if !reflect.DeepEqual(cfg.NextProtos, []string{"h2", "http/1.1"}) {
		t.Fatalf("expected policy ALPN to be kept, got %v", cfg.NextProtos)
	}
}

func TestSelectTLSOpts_ExplicitFlagsBypassClusterPolicyAndALPNOverride(t *testing.T) {
	var gotMinVer, gotCiphers string
	resolve := func(_ context.Context, _ *rest.Config, minVer, ciphers string) ([]func(*tls.Config), error) {
		gotMinVer, gotCiphers = minVer, ciphers
		return nil, nil
	}
	opts := Options{tlsMinVersion: "VersionTLS13", enableHTTP2: false}
	tlsOpts, err := selectTLSOpts(context.Background(), nil, opts, true, resolve)
	if err != nil {
		t.Fatalf("selectTLSOpts() error = %v", err)
	}
	if gotMinVer != "VersionTLS13" || gotCiphers != "" {
		t.Fatalf("expected resolver to receive explicit flags, got min version %q ciphers %q", gotMinVer, gotCiphers)
	}
	if len(tlsOpts) != 0 {
		t.Fatalf("expected no ALPN override appended for explicit flags, got %d opts", len(tlsOpts))
	}
}

func TestSelectTLSOpts_DefaultResolvesPolicyWithoutOverride(t *testing.T) {
	var gotMinVer, gotCiphers string
	resolve := func(_ context.Context, _ *rest.Config, minVer, ciphers string) ([]func(*tls.Config), error) {
		gotMinVer, gotCiphers = minVer, ciphers
		return []func(*tls.Config){
			func(c *tls.Config) {
				c.MinVersion = tls.VersionTLS12
				c.NextProtos = []string{"h2", "http/1.1"}
			},
		}, nil
	}
	opts := Options{}
	tlsOpts, err := selectTLSOpts(context.Background(), nil, opts, false, resolve)
	if err != nil {
		t.Fatalf("selectTLSOpts() error = %v", err)
	}
	if gotMinVer != "" || gotCiphers != "" {
		t.Fatalf("expected resolver to receive empty flag values, got min version %q ciphers %q", gotMinVer, gotCiphers)
	}
	cfg := applyTLSOpts(t, tlsOpts)
	if !reflect.DeepEqual(cfg.NextProtos, []string{"h2", "http/1.1"}) {
		t.Fatalf("expected policy ALPN to be kept, got %v", cfg.NextProtos)
	}
}
