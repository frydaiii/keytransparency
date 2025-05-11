// Copyright 2025 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package expiration

import (
	"testing"
	"time"

	"github.com/google/keytransparency/core/client"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"
)

func TestCheckerCheckUser(t *testing.T) {
	// Create a test keyset
	keysetHandle, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle() failed: %v", err)
	}
	
	// Create test user
	user := &client.User{
		UserID:         "test@example.com",
		PublicKeyData:  []byte("test-key-data"),
		AuthorizedKeys: keysetHandle,
	}
	
	// Create checker with custom config for testing
	checker := NewChecker(&Config{
		WarningThreshold: 20 * 24 * time.Hour, // 20 days
	})
	
	// Run the check
	results, err := checker.CheckUser(user)
	if err != nil {
		t.Fatalf("CheckUser failed: %v", err)
	}
	
	// Verify we got results
	if len(results) == 0 {
		t.Error("Expected key results, got none")
	}
	
	// Test nil user
	if _, err := checker.CheckUser(nil); err == nil {
		t.Error("Expected error for nil user, got none")
	}
}

func TestFormatNotification(t *testing.T) {
	now := time.Now()
	
	tests := []struct {
		name     string
		keyInfos []KeyInfo
		wantText bool
	}{
		{
			name:     "No keys",
			keyInfos: []KeyInfo{},
			wantText: true,
		},
		{
			name: "Valid keys only",
			keyInfos: []KeyInfo{
				{KeyID: 1, Status: Valid, ExpireTime: now.Add(100 * 24 * time.Hour), DaysLeft: 100},
			},
			wantText: true,
		},
		{
			name: "Warning keys",
			keyInfos: []KeyInfo{
				{KeyID: 1, Status: Valid, ExpireTime: now.Add(100 * 24 * time.Hour), DaysLeft: 100},
				{KeyID: 2, Status: Warning, ExpireTime: now.Add(10 * 24 * time.Hour), DaysLeft: 10},
			},
			wantText: true,
		},
		{
			name: "Expired keys",
			keyInfos: []KeyInfo{
				{KeyID: 1, Status: Valid, ExpireTime: now.Add(100 * 24 * time.Hour), DaysLeft: 100},
				{KeyID: 2, Status: Expired, ExpireTime: now.Add(-10 * 24 * time.Hour), DaysLeft: -10},
			},
			wantText: true,
		},
	}
	
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := FormatNotification(tc.keyInfos)
			if (len(result) > 0) != tc.wantText {
				t.Errorf("FormatNotification() = %q, wantText: %v", result, tc.wantText)
			}
		})
	}
}
