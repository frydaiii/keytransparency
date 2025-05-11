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

// Package expiration provides functionality to check and notify users about key expirations.
package expiration

import (
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/google/tink/go/keyset"

	"github.com/google/keytransparency/core/client"
)

// Status represents the expiration status of a key
type Status int

const (
	// Valid means the key is not expired or nearing expiration
	Valid Status = iota
	// Warning means the key will expire soon
	Warning
	// Expired means the key has already expired
	Expired
)

// Config holds configuration parameters for the expiration checker
type Config struct {
	// WarningThreshold is the duration before expiration when warnings should be issued
	WarningThreshold time.Duration
}

// DefaultConfig returns a Config with reasonable default values
func DefaultConfig() *Config {
	return &Config{
		WarningThreshold: 30 * 24 * time.Hour, // 30 days
	}
}

// Checker is responsible for checking key expirations
type Checker struct {
	config *Config
}

// NewChecker creates a new key expiration checker
func NewChecker(config *Config) *Checker {
	if config == nil {
		config = DefaultConfig()
	}
	return &Checker{
		config: config,
	}
}

// KeyInfo contains information about a key, including its expiration status
type KeyInfo struct {
	KeyID      uint32
	Status     Status
	ExpireTime time.Time
	DaysLeft   int
}

// CheckUser checks the expiration status of all keys for a user
func (c *Checker) CheckUser(u *client.User) ([]KeyInfo, error) {
	if u == nil {
		return nil, fmt.Errorf("user cannot be nil")
	}

	results := []KeyInfo{}
	
	// Get authorized keys from user
	if u.AuthorizedKeys == nil {
		return results, nil
	}

	// Extract key information from the keyset handle
	info, err := getKeysetInfo(u.AuthorizedKeys)
	if err != nil {
		return nil, fmt.Errorf("error reading key info: %v", err)
	}

	// Check expiration for each key
	now := time.Now()
	for _, keyInfo := range info.GetKeyInfo() {
		// Get key expiration time - this is a simplified example
		// In a real implementation, we would extract the actual expiration time from the key
		// For now, we'll use a mock expiration time for demonstration
		expirationTime := getMockExpirationTime(keyInfo.GetKeyId(), now)
		
		// Calculate days left until expiration
		daysLeft := int(expirationTime.Sub(now).Hours() / 24)
		
		// Determine status
		status := Valid
		if expirationTime.Before(now) {
			status = Expired
		} else if expirationTime.Sub(now) < c.config.WarningThreshold {
			status = Warning
		}
		
		results = append(results, KeyInfo{
			KeyID:      keyInfo.GetKeyId(),
			Status:     status,
			ExpireTime: expirationTime,
			DaysLeft:   daysLeft,
		})
	}
	
	return results, nil
}

// getKeysetInfo extracts the keyset info from a keyset handle
func getKeysetInfo(handle *keyset.Handle) (*keyset.Info, error) {
	return handle.KeysetInfo()
}

// getMockExpirationTime returns a mock expiration time for demonstration purposes
// In a real implementation, this would extract the actual expiration from the key
func getMockExpirationTime(keyID uint32, now time.Time) time.Time {
	// For demo purposes, keys with even IDs expire in 10 days, odd IDs in 40 days
	var daysToAdd int
	if keyID%2 == 0 {
		daysToAdd = 10
	} else {
		daysToAdd = 40
	}
	
	return now.Add(time.Duration(daysToAdd) * 24 * time.Hour)
}

// FormatNotification formats key expiration notifications in a user-friendly way
func FormatNotification(keyInfos []KeyInfo) string {
	if len(keyInfos) == 0 {
		return "No keys found"
	}
	
	var result string
	hasWarnings := false
	
	for _, info := range keyInfos {
		switch info.Status {
		case Expired:
			result += fmt.Sprintf("⚠️ KEY EXPIRED: Key ID %d expired on %s\n", 
				info.KeyID, info.ExpireTime.Format("2006-01-02"))
			hasWarnings = true
		case Warning:
			result += fmt.Sprintf("⚠️ WARNING: Key ID %d will expire in %d days (on %s)\n", 
				info.KeyID, info.DaysLeft, info.ExpireTime.Format("2006-01-02"))
			hasWarnings = true
		case Valid:
			result += fmt.Sprintf("✅ Key ID %d is valid (expires in %d days on %s)\n", 
				info.KeyID, info.DaysLeft, info.ExpireTime.Format("2006-01-02"))
		}
	}
	
	if hasWarnings {
		result += "\nPlease rotate any keys that are expired or will expire soon.\n"
		result += "Use 'keytransparency-client authorized-keys create-keyset' to create new keys.\n"
	}
	
	return result
}
