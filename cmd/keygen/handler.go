package keygen

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"p0-ssh-agent/internal/config"
	"p0-ssh-agent/internal/jwt"
	"p0-ssh-agent/internal/logging"
)

func NewKeygenCommand(verbose *bool, configPath *string) *cobra.Command {
	var (
		keyPath string
		force   bool

		keygenPath string
	)

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate JWT keypair for P0 SSH Agent",
		Long: `Generate ES384 JWT keypair for P0 SSH Agent authentication.
This command should be run once to create the keypair that will be registered
with the P0 backend. The public key will be used for machine registration.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeygen(*verbose, *configPath, keyPath, force, keygenPath)
		},
	}

	cmd.Flags().StringVar(&keyPath, "key-path", "", "Directory to store JWT key files")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing keys")
	cmd.Flags().StringVar(&keygenPath, "path", "", "Directory to store JWT key files (deprecated, use --key-path)")

	return cmd
}

func runKeygen(verbose bool, configPath, keyPath string, force bool, keygenPath string) error {
	flagOverrides := map[string]interface{}{
		"keyPath": keyPath,
	}

	var logger *logrus.Logger
	var finalKeyPath string

	cfg, err := config.LoadWithOverrides(configPath, flagOverrides)
	if err != nil {
		logger = logrus.New()
		if verbose {
			logger.SetLevel(logrus.DebugLevel)
		}
		logger.WithError(err).Warn("Failed to load configuration, using basic logging")
	} else {
		logger = logging.SetupLogger(verbose)
	}

	finalKeyPath = keyPath
	if finalKeyPath == "" && keygenPath != "" {
		finalKeyPath = keygenPath
	}

	if finalKeyPath == "" && cfg != nil {
		finalKeyPath = cfg.KeyPath
	}

	logger.WithField("path", finalKeyPath).Info("P0 SSH Agent Key Generator")

	privateKeyPath := filepath.Join(finalKeyPath, jwt.PrivateKeyFile)
	publicKeyPath := filepath.Join(finalKeyPath, jwt.PublicKeyFile)

	if !force {
		if _, err := os.Stat(privateKeyPath); err == nil {
			logger.WithField("path", privateKeyPath).Error("Private key already exists")
			logger.Error("Use --force to overwrite existing keys")
			logger.Error("⚠️  WARNING: Overwriting keys will break existing registrations!")
			return fmt.Errorf("keys already exist at %s", finalKeyPath)
		}
	}

	jwtManager := jwt.NewManager(logger)

	if err := jwtManager.GenerateKeyPair(finalKeyPath); err != nil {
		logger.WithError(err).Error("Failed to generate keypair")
		return err
	}

	if _, err := os.ReadFile(publicKeyPath); err != nil {
		logger.WithError(err).Error("Failed to read generated public key")
		return err
	}

	fmt.Println("\n🔑 JWT Keypair Generated Successfully!")
	fmt.Printf("📁 Location: %s\n", finalKeyPath)
	fmt.Printf("🔒 Private Key: %s\n", privateKeyPath)
	fmt.Printf("🔓 Public Key: %s\n", publicKeyPath)
	fmt.Println("\n⚠️  IMPORTANT: Back up these keys! Losing them will require re-registration.")
	fmt.Println("=================================")
	fmt.Println("\n💡 Next Steps:")
	fmt.Println("1. Keep the private key secure and backed up")
	fmt.Println("2. Register this device with your P0 backend, e.g.")
	fmt.Println("   p0-ssh-agent register --auth=\"{API_KEY}\" --url=\"https://api.p0.app/o/{org}/integrations/self-hosted/{environment}/computers/register\"")

	return nil
}
