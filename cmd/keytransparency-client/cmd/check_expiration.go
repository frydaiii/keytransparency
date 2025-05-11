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

package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/golang/glog"
	"github.com/google/keytransparency/core/client/expiration"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

var checkExpirationCmd = &cobra.Command{
	Use:   "check-expiration userID",
	Short: "Check key expiration status",
	Long:  `Check if any of the authorized keys for a user are expired or will expire soon`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		timeout := viper.GetDuration("timeout")
		warningDays := viper.GetInt("warning-days")
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		userID := args[0]
		
		// Get the client
		c, err := GetClient(ctx)
		if err != nil {
			return fmt.Errorf("error connecting: %v", err)
		}

		// Get user creds for the grpc call
		userCreds, err := userCreds(ctx)
		if err != nil {
			return err
		}

		// Get the user's current profile
		profile, _, err := c.GetUser(ctx, userID, grpc.PerRPCCredentials(userCreds))
		if err != nil {
			return fmt.Errorf("GetUser failed: %v", err)
		}

		// Create expiration checker
		checker := expiration.NewChecker(&expiration.Config{
			WarningThreshold: time.Duration(warningDays) * 24 * time.Hour,
		})

		// Check expirations
		results, err := checker.CheckUser(profile)
		if err != nil {
			return fmt.Errorf("key expiration check failed: %v", err)
		}

		// Format and display the results
		notification := expiration.FormatNotification(results)
		fmt.Println(notification)

		return nil
	},
}

func init() {
	RootCmd.AddCommand(checkExpirationCmd)

	// Define flags specific to this command
	checkExpirationCmd.PersistentFlags().Int("warning-days", 30, "Number of days before expiration to show warnings")

	// Bind with viper
	if err := viper.BindPFlag("warning-days", checkExpirationCmd.PersistentFlags().Lookup("warning-days")); err != nil {
		glog.Exitf("Failed to bind flag: %v", err)
	}
}
