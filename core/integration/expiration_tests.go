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

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/golang/glog"
	"github.com/google/keytransparency/core/client"
	"github.com/google/keytransparency/core/client/expiration"
	"github.com/google/keytransparency/core/testutil"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/keyset"
)

// TestKeyExpirationChecker verifies that the key expiration checker works correctly
func TestKeyExpirationChecker(ctx context.Context, env *Env, t *testing.T) {
	// Skip test if the expiration feature is not fully wired up in the environment
	if env == nil {
		t.Skip("Env is nil")
		return
	}
	
	// Create a key to test with
	handle, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("keyset.NewHandle(): %v", err)
	}

	// Create a test user with the key
	testUser := &client.User{
		UserID:         "test-expiration@example.com",
		PublicKeyData:  []byte("test-data"),
		AuthorizedKeys: handle,
	}

	// Create the expiration checker
	checker := expiration.NewChecker(expiration.DefaultConfig())
	
	// Check the keys
	results, err := checker.CheckUser(testUser)
	if err != nil {
		t.Fatalf("checker.CheckUser(): %v", err)
	}

	// Verify we got some results
	if len(results) == 0 {
		t.Error("Expected key results, got none")
	}

	// Verify the notification formatting works
	notification := expiration.FormatNotification(results)
	if notification == "" {
		t.Error("Expected non-empty notification")
	}

	// Log the notification for manual inspection
	glog.Info(notification)
}

// TestKeyExpirationChecker is already added to AllTests in alltests.go
