package register

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"p0-ssh-agent/internal/osplugins"
	"p0-ssh-agent/types"
	"p0-ssh-agent/utils"
)

func NewRegisterCommand(verbose *bool, configPath *string) *cobra.Command {
	var (
		auth             string
		url              string
		hostname         string
		labels           []string
		serviceName      string
		allowRoot        bool
		breakGlassUsers  []string
	)

	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register machine with P0 backend using automatic registration",
		Long: `Register and install P0 SSH Agent using automatic registration.
This command will:
- Install the P0 SSH Agent binary and service files
- Generate JWT keys
- Send registration key to the P0 backend
- Receive configuration from P0 backend
- Save configuration and trusted CA
- Configure SSH daemon to trust the P0 CA
- Set up systemd service

Usage:
  p0 register --auth "bearer-token" --url "https://p0.dev/o/<org-id>/integrations/self-hosted/computers/<environment-id>/register"

Examples:
  # Basic registration
  p0 register --auth "token123" --url "https://p0.dev/o/myorg/integrations/..."

  # With custom hostname and labels
  p0 register --auth "token123" --url "https://p0.dev/o/myorg/integrations/..." \
    --hostname "web-server-01" \
    --label "env=production" \
    --label "team=backend" \
    --label "region=us-west-2"

  # With break-glass users for out-of-band access
  p0 register --auth "token123" --url "https://p0.dev/o/myorg/integrations/..." \
    --break-glass-user "admin" \
    --break-glass-user "backup-admin"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRegister(*verbose, auth, url, hostname, labels, serviceName, allowRoot, breakGlassUsers)
		},
	}

	cmd.Flags().StringVar(&auth, "auth", "", "Bearer token for authentication (required)")
	cmd.Flags().StringVar(&url, "url", "", "Registration URL (required)")
	cmd.Flags().StringVar(&hostname, "hostname", "", "Override machine hostname")
	cmd.Flags().StringSliceVar(&labels, "label", []string{}, "Machine labels in key=value format (can be used multiple times)")
	cmd.Flags().StringVar(&serviceName, "service-name", "p0-ssh-agent", "Name for the systemd service")
	cmd.Flags().BoolVar(&allowRoot, "allow-root", false, "Allow installation to run as root")
	cmd.Flags().StringSliceVar(&breakGlassUsers, "break-glass-user", []string{}, "Username for break-glass SSH access (can be used multiple times, will generate or retrieve SSH key)")

	cmd.MarkFlagRequired("auth")
	cmd.MarkFlagRequired("url")

	return cmd
}

type RegistrationResponse struct {
	Ok            bool   `json:"ok"`
	EnvironmentId string `json:"environmentId"`
	HostId        string `json:"hostId"`
	OrgId         string `json:"orgId"`
	TrustedCa     string `json:"trustedCa"`
	TunnelHost    string `json:"tunnelHost"`
}

func runRegister(verbose bool, auth, url, hostname string, labels []string, serviceName string, allowRoot bool, breakGlassUsers []string) error {
	logger := logrus.New()
	if verbose {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	logger.Info("🚀 Starting P0 SSH Agent registration and installation...")

	// Step 1: Perform installation steps (merged from install command)
	logger.Info("📦 Step 1: Installing P0 SSH Agent...")
	osPlugin, err := osplugins.GetPlugin(logger)
	if err != nil {
		return fmt.Errorf("failed to select OS plugin: %w", err)
	}

	// Use standard config location for registration (both OS plugins use /etc/p0-ssh-agent)
	configPath := "/etc/p0-ssh-agent/config.yaml"

	// Run installation steps
	if err := runInstallationSteps(logger, osPlugin, serviceName, configPath, allowRoot); err != nil {
		return fmt.Errorf("installation failed: %w", err)
	}

	// Step 2: Send registration request to P0 backend
	logger.Info("🔗 Step 2: Registering with P0 backend...")
	response, err := sendRegistrationRequest(auth, url, hostname, labels, breakGlassUsers, logger)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	if !response.Ok {
		return fmt.Errorf("registration was not successful")
	}

	// Step 3: Save configuration
	logger.Info("💾 Step 3: Saving configuration...")
	if err := saveConfiguration(response, configPath, logger); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	// Step 4: Registration complete
	logger.Info("✅ Step 4: Registration completed successfully")

	// Display OS-specific post-registration instructions
	fmt.Printf("\n✅ Registration successful. Configuration saved to %s\n", configPath)
	osPlugin.DisplayInstallationSuccess(serviceName, configPath, verbose)

	return nil
}

type SSHKeyPair struct {
	PrivateKey string
	PublicKey  string
}

func getOrGenerateSSHKeyForUser(userName string, logger *logrus.Logger) (*SSHKeyPair, error) {
	// Use dedicated P0 SSH key for break-glass access
	homeDir := "/home/" + userName
	if userName == "root" {
		homeDir = "/root"
	}

	sshDir := filepath.Join(homeDir, ".ssh")
	sshKeyPath := filepath.Join(sshDir, "p0_id_rsa")
	sshPubKeyPath := sshKeyPath + ".pub"

	// Check if P0 SSH key already exists
	privateKeyData, err := os.ReadFile(sshKeyPath)
	publicKeyData, pubErr := os.ReadFile(sshPubKeyPath)

	if err == nil && pubErr == nil {
		logger.WithFields(logrus.Fields{
			"userName": userName,
			"keyPath":  sshKeyPath,
		}).Info("🔑 Using existing P0 SSH key for break-glass user")
		return &SSHKeyPair{
			PrivateKey: string(privateKeyData),
			PublicKey:  string(publicKeyData),
		}, nil
	}

	// Generate new P0 SSH key pair
	logger.WithFields(logrus.Fields{
		"userName": userName,
		"keyPath":  sshKeyPath,
	}).Info("🔑 Generating new P0 SSH key pair for break-glass user")

	// Create .ssh directory if it doesn't exist
	cmd := exec.Command("sudo", "mkdir", "-p", sshDir)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to create .ssh directory: %w", err)
	}

	// Generate SSH key pair using ssh-keygen
	cmd = exec.Command("sudo", "ssh-keygen", "-t", "rsa", "-b", "4096", "-f", sshKeyPath, "-N", "", "-C", "p0-break-glass-"+userName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to generate SSH key: %w (output: %s)", err, string(output))
	}

	// Set proper ownership for the keys
	cmd = exec.Command("sudo", "chown", userName+":"+userName, sshKeyPath)
	if err := cmd.Run(); err != nil {
		logger.WithError(err).Warn("Failed to set ownership for private key")
	}

	cmd = exec.Command("sudo", "chown", userName+":"+userName, sshPubKeyPath)
	if err := cmd.Run(); err != nil {
		logger.WithError(err).Warn("Failed to set ownership for public key")
	}

	// Set proper permissions
	cmd = exec.Command("sudo", "chmod", "600", sshKeyPath)
	if err := cmd.Run(); err != nil {
		logger.WithError(err).Warn("Failed to set permissions for private key")
	}

	cmd = exec.Command("sudo", "chmod", "644", sshPubKeyPath)
	if err := cmd.Run(); err != nil {
		logger.WithError(err).Warn("Failed to set permissions for public key")
	}

	// Read the generated keys
	privateKeyData, err = os.ReadFile(sshKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read generated SSH private key: %w", err)
	}

	publicKeyData, err = os.ReadFile(sshPubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read generated SSH public key: %w", err)
	}

	logger.WithField("userName", userName).Info("✅ Successfully generated P0 SSH key pair for break-glass user")
	return &SSHKeyPair{
		PrivateKey: string(privateKeyData),
		PublicKey:  string(publicKeyData),
	}, nil
}

func userExists(userName string) bool {
	cmd := exec.Command("id", "-u", userName)
	err := cmd.Run()
	return err == nil
}

func addPublicKeyToAuthorizedKeys(userName, publicKey string, logger *logrus.Logger) error {
	homeDir := "/home/" + userName
	if userName == "root" {
		homeDir = "/root"
	}

	authorizedKeysPath := filepath.Join(homeDir, ".ssh", "authorized_keys")
	logger.WithFields(logrus.Fields{
		"userName":           userName,
		"authorizedKeysPath": authorizedKeysPath,
	}).Debug("Adding public key to authorized_keys")

	// Create a temporary file with the public key
	tmpFile, err := os.CreateTemp("", "authorized_keys_*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	tmpFileName := tmpFile.Name()
	defer os.Remove(tmpFileName)

	// Write the public key to the temp file
	if _, err := tmpFile.WriteString(publicKey + "\n"); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write public key to temp file: %w", err)
	}
	tmpFile.Close()

	// Append to authorized_keys using sudo
	cmd := exec.Command("sudo", "bash", "-c", fmt.Sprintf("cat %s >> %s", tmpFileName, authorizedKeysPath))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to append to authorized_keys: %w (output: %s)", err, string(output))
	}

	// Set proper ownership
	cmd = exec.Command("sudo", "chown", userName+":"+userName, authorizedKeysPath)
	if err := cmd.Run(); err != nil {
		logger.WithError(err).Warn("Failed to set ownership for authorized_keys")
	}

	// Set proper permissions
	cmd = exec.Command("sudo", "chmod", "600", authorizedKeysPath)
	if err := cmd.Run(); err != nil {
		logger.WithError(err).Warn("Failed to set permissions for authorized_keys")
	}

	logger.WithField("userName", userName).Info("✅ Added P0 public key to authorized_keys")
	return nil
}

func deleteSSHKeyPair(userName string, logger *logrus.Logger) error {
	homeDir := "/home/" + userName
	if userName == "root" {
		homeDir = "/root"
	}

	sshKeyPath := filepath.Join(homeDir, ".ssh", "p0_id_rsa")
	sshPubKeyPath := sshKeyPath + ".pub"

	logger.WithFields(logrus.Fields{
		"userName":      userName,
		"privateKeyPath": sshKeyPath,
		"publicKeyPath":  sshPubKeyPath,
	}).Debug("Deleting P0 SSH key pair")

	// Delete private key
	cmd := exec.Command("sudo", "rm", "-f", sshKeyPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to delete private key: %w (output: %s)", err, string(output))
	}

	// Delete public key
	cmd = exec.Command("sudo", "rm", "-f", sshPubKeyPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to delete public key: %w (output: %s)", err, string(output))
	}

	logger.WithField("userName", userName).Info("🗑️  Deleted P0 SSH key pair after successful registration")
	return nil
}

func sendRegistrationRequest(auth, url, hostname string, labels []string, breakGlassUsers []string, logger *logrus.Logger) (*RegistrationResponse, error) {
	// Generate the registration request using the key path
	keyPath := "/etc/p0-ssh-agent/keys"
	encodedRequest, err := utils.GenerateRegistrationRequestCodeWithOptions(keyPath, hostname, labels, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to generate registration request: %w", err)
	}

	logger.WithFields(logrus.Fields{
		"url":  url,
		"auth": auth[:8] + "...", // Log only first 8 chars for security
	}).Debug("Sending registration request")

	// Build request body with key
	requestBody := map[string]interface{}{
		"key": encodedRequest,
	}

	// If break-glass users are provided, add credentials
	usersToCleanup := []string{} // Track users whose key files need cleanup
	if len(breakGlassUsers) > 0 {
		logger.WithFields(logrus.Fields{
			"userCount": len(breakGlassUsers),
			"users":     breakGlassUsers,
		}).Info("🔐 Validating and retrieving SSH keys for break-glass access")

		// Validate that all users exist on the system
		validUsers := []string{}
		for _, userName := range breakGlassUsers {
			if !userExists(userName) {
				logger.WithField("userName", userName).Warn("⚠️  Break-glass user does not exist on system, skipping")
				continue
			}
			validUsers = append(validUsers, userName)
		}

		if len(validUsers) == 0 {
			logger.Warn("No valid break-glass users found, continuing registration without break-glass access")
		} else {
			breakGlassUserCredentials := make(map[string]map[string]string)

			for _, userName := range validUsers {
				logger.WithField("userName", userName).Debug("Processing break-glass user")
				keyPair, err := getOrGenerateSSHKeyForUser(userName, logger)
				if err != nil {
					return nil, fmt.Errorf("failed to get SSH key for break-glass user '%s': %w", userName, err)
				}

				// Add this user to cleanup list immediately after key generation
				usersToCleanup = append(usersToCleanup, userName)

				// Add public key to authorized_keys immediately after generation
				if err := addPublicKeyToAuthorizedKeys(userName, keyPair.PublicKey, logger); err != nil {
					return nil, fmt.Errorf("failed to add public key to authorized_keys for '%s': %w", userName, err)
				}

				breakGlassUserCredentials[userName] = map[string]string{
					"publicKey":  keyPair.PublicKey,
					"privateKey": keyPair.PrivateKey,
				}
			}

			requestBody["breakGlassUserCredentials"] = breakGlassUserCredentials
			logger.WithField("userCount", len(validUsers)).Info("✅ Break-glass credentials added to registration request")
		}
	}

	// Setup deferred cleanup - will run regardless of success or failure
	defer func() {
		if len(usersToCleanup) > 0 {
			logger.WithField("userCount", len(usersToCleanup)).Info("🧹 Cleaning up: Deleting temporary key pair files")

			for _, userName := range usersToCleanup {
				if err := deleteSSHKeyPair(userName, logger); err != nil {
					logger.WithError(err).WithField("userName", userName).Warn("Failed to delete SSH key pair (non-fatal)")
					// Continue with other users even if one fails - this is just cleanup
				}
			}

			logger.Info("✅ Break-glass key cleanup completed")
		}
	}()

	requestJSON, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create HTTP request with bearer token
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+auth)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send registration request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registration request failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var response RegistrationResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse registration response: %w", err)
	}

	logger.WithFields(logrus.Fields{
		"orgId":      response.OrgId,
		"hostId":     response.HostId,
		"tunnelHost": response.TunnelHost,
	}).Info("Registration response received")

	return &response, nil
}

func saveConfiguration(response *RegistrationResponse, configPath string, logger *logrus.Logger) error {
	config := types.Config{
		Version:                  "1.0",
		OrgID:                    response.OrgId,
		HostID:                   response.HostId,
		TunnelHost:               response.TunnelHost,
		KeyPath:                  "/etc/p0-ssh-agent/keys",
		EnvironmentId:            response.EnvironmentId,
		HeartbeatIntervalSeconds: 60,
		DryRun:                   false,
	}

	// Config will be saved to /etc/p0-ssh-agent/config.yaml (directory already created in runInstallationSteps)

	// Create a temporary file for the config
	tmpFile, err := os.CreateTemp("", "config_*.yaml")
	if err != nil {
		return fmt.Errorf("failed to create temporary config file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	configYAML := fmt.Sprintf(`# P0 SSH Agent Configuration File
# Auto-generated from registration response

version: "%s"
orgId: "%s"
hostId: "%s"
tunnelHost: "%s"
keyPath: "%s"
environmentId: "%s"
heartbeatIntervalSeconds: %d
dryRun: %t
`,
		config.Version,
		config.OrgID,
		config.HostID,
		config.TunnelHost,
		config.KeyPath,
		config.EnvironmentId,
		config.HeartbeatIntervalSeconds,
		config.DryRun,
	)

	if _, err := tmpFile.WriteString(configYAML); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write config to temporary file: %w", err)
	}
	tmpFile.Close()

	// Copy temp file to final location using sudo
	cmd := exec.Command("sudo", "cp", tmpFile.Name(), configPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to copy config file: %w", err)
	}

	// Set proper permissions
	cmd = exec.Command("sudo", "chmod", "644", configPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set config file permissions: %w", err)
	}

	logger.WithField("path", configPath).Info("Configuration saved successfully")
	return nil
}

func runInstallationSteps(logger *logrus.Logger, osPlugin osplugins.OSPlugin, serviceName string, configPath string, allowRoot bool) error {
	// This incorporates the key functionality from the install command

	// Security check
	if os.Geteuid() == 0 && !allowRoot {
		return fmt.Errorf("register command should not be run as root, please run as regular user with sudo privileges (or use --allow-root flag to bypass this check)")
	}

	if os.Geteuid() == 0 && allowRoot {
		logger.Warn("⚠️  Running as root - this bypasses security restrictions and is not recommended")
	}

	// Get current executable
	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %w", err)
	}

	// Install binary using OS-specific install directories
	installDirs := osPlugin.GetInstallDirectories()
	var destPath string
	var installSuccess bool

	for _, installDir := range installDirs {
		destPath = filepath.Join(installDir, "p0-ssh-agent")

		// Check if binary already exists at this location
		if _, err := os.Stat(destPath); err == nil {
			logger.WithField("path", destPath).Info("✅ Binary already exists at system location")
			installSuccess = true
			break
		}

		// Try to install to this directory
		logger.WithField("installDir", installDir).Info("📦 Attempting to install binary...")
		if err := copyBinary(currentExe, destPath, logger); err != nil {
			logger.WithError(err).WithField("installDir", installDir).Warn("Failed to install to directory, trying next...")
			continue
		}

		logger.WithField("path", destPath).Info("✅ Binary installed successfully")
		installSuccess = true
		break
	}

	if !installSuccess {
		return fmt.Errorf("failed to install binary to any of the available directories: %v", installDirs)
	}

	// Create config and key directories using OS plugin
	configDir := "/etc/p0-ssh-agent"
	keyPath := filepath.Join(configDir, "keys")

	dirsToSetup := []string{configDir, keyPath}
	if err := osPlugin.SetupDirectories(dirsToSetup, "root", logger); err != nil {
		return fmt.Errorf("failed to setup directories: %w", err)
	}

	// Set proper permissions on key directory (readable for public key access, private key will be protected individually)
	cmd := exec.Command("sudo", "chmod", "755", keyPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set key directory permissions: %w", err)
	}

	// Generate JWT keys
	if err := generateJWTKeys(keyPath, destPath, logger); err != nil {
		return fmt.Errorf("failed to generate JWT keys: %w", err)
	}

	// Create systemd service
	if err := osPlugin.CreateSystemdService(serviceName, destPath, configPath, logger); err != nil {
		return fmt.Errorf("failed to create systemd service: %w", err)
	}

	return nil
}

func copyBinary(srcPath, destPath string, logger *logrus.Logger) error {
	logger.WithFields(logrus.Fields{
		"src":  srcPath,
		"dest": destPath,
	}).Debug("Copying binary using sudo")

	// Use sudo to copy the binary to the system location
	cmd := exec.Command("sudo", "cp", srcPath, destPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to copy binary with sudo: %w", err)
	}

	// Use sudo to set executable permissions
	cmd = exec.Command("sudo", "chmod", "755", destPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set executable permissions with sudo: %w", err)
	}

	return nil
}

func generateJWTKeys(keyPath, executablePath string, logger *logrus.Logger) error {
	// Check if keys already exist
	privateKeyPath := filepath.Join(keyPath, "jwk.private.json")
	publicKeyPath := filepath.Join(keyPath, "jwk.public.json")

	if _, err := os.Stat(privateKeyPath); err == nil {
		if _, err := os.Stat(publicKeyPath); err == nil {
			logger.Info("✅ JWT keys already exist")
			return nil
		}
	}

	// Generate new keys using sudo
	cmd := exec.Command("sudo", executablePath, "keygen", "--key-path", keyPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to generate JWT keys: %w (output: %s)", err, string(output))
	}

	// Set appropriate permissions: public key readable by all, private key root-only
	chmodCmd := exec.Command("sudo", "chmod", "644", publicKeyPath)
	if err := chmodCmd.Run(); err != nil {
		return fmt.Errorf("failed to set public key permissions: %w", err)
	}

	chmodPrivateCmd := exec.Command("sudo", "chmod", "600", privateKeyPath)
	if err := chmodPrivateCmd.Run(); err != nil {
		return fmt.Errorf("failed to set private key permissions: %w", err)
	}

	logger.Info("✅ JWT keys generated successfully")
	return nil
}
