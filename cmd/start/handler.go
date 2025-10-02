package start

import (
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"p0-ssh-agent/internal/client"
	"p0-ssh-agent/internal/config"
	"p0-ssh-agent/internal/logging"
)

func NewStartCommand(verbose *bool, configPath *string) *cobra.Command {
	var (
		orgID           string
		hostID          string
		tunnelHost      string
		keyPath         string
		labels          []string
		environment     string
		tunnelTimeoutMs int
		dryRun          bool
	)

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the WebSocket proxy agent",
		Long: `Start the P0 SSH Agent WebSocket proxy that connects to the P0 backend 
and logs incoming requests for monitoring and debugging purposes.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStart(
				*verbose, *configPath,
				orgID, hostID, tunnelHost,
				keyPath, labels, environment,
				tunnelTimeoutMs, dryRun,
			)
		},
	}

	cmd.Flags().StringVar(&orgID, "org-id", "", "Organization identifier")
	cmd.Flags().StringVar(&hostID, "host-id", "", "Host identifier")
	cmd.Flags().StringVar(&tunnelHost, "tunnel-host", "", "WebSocket URL (e.g., ws://localhost:8079, wss://example.ngrok.app, wss://api.p0.app)")
	cmd.Flags().StringVar(&keyPath, "key-path", "", "Path to store JWT key files")
	cmd.Flags().StringSliceVar(&labels, "labels", []string{}, "Machine labels for registration (can be used multiple times)")
	cmd.Flags().StringVar(&environment, "environment", "", "Environment ID for registration")
	cmd.Flags().IntVar(&tunnelTimeoutMs, "tunnel-timeout", 0, "Tunnel timeout in milliseconds")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Log commands but don't execute them (safe testing mode)")

	return cmd
}

func runStart(
	verbose bool, configPath string,
	orgID, hostID, tunnelHost string,
	keyPath string, labels []string, environment string,
	tunnelTimeoutMs int, dryRun bool,
) error {
	flagOverrides := map[string]interface{}{
		"orgId":           orgID,
		"hostId":          hostID,
		"tunnelHost":      tunnelHost,
		"keyPath":         keyPath,
		"labels":          labels,
		"environment":     environment,
		"tunnelTimeoutMs": tunnelTimeoutMs,
		"dryRun":          dryRun,
	}

	cfg, err := config.LoadWithOverrides(configPath, flagOverrides)
	if err != nil {
		logger := logrus.New()
		if verbose {
			logger.SetLevel(logrus.DebugLevel)
		}
		logger.WithError(err).Error("Failed to load configuration")
		return err
	}

	logger := logging.SetupLogger(verbose)

	client, err := client.New(cfg, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to create P0 SSH Agent client")

		if strings.Contains(err.Error(), "failed to load JWT key") {
			logger.Error("🔑 Keys not found or invalid! Generate them first:")
			logger.Errorf("   1. Generate keys: p0-ssh-agent keygen --key-path %s", cfg.KeyPath)
			logger.Error("   2. Register public key with P0 backend")
			logger.Error("   3. Run agent again")
		} else if strings.Contains(err.Error(), "permission denied") {
			logger.Error("💡 Fix: Try running with --key-path pointing to a writable directory")
			logger.Error("   Example: --key-path $HOME/.p0/keys")
			logger.Error("   Or: mkdir -p ~/.p0/keys && chmod 700 ~/.p0/keys")
		}

		return err
	}

	var gracefulShutdown bool
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Info("Received shutdown signal, shutting down P0 SSH Agent gracefully...")
		gracefulShutdown = true
		client.Shutdown()
	}()

	logger.WithFields(logrus.Fields{
		"version":     cfg.Version,
		"orgId":       cfg.OrgID,
		"hostId":      cfg.HostID,
		"clientId":    cfg.GetClientID(),
		"tunnelHost":  cfg.TunnelHost,
		"keyPath":     cfg.KeyPath,
		"labels":      cfg.Labels,
		"environment": cfg.EnvironmentId,
		"dryRun":      cfg.DryRun,
	}).Info("Starting P0 SSH Agent")

	if err := client.Run(); err != nil {
		if gracefulShutdown {
			logger.Info("P0 SSH Agent stopped")
			return nil
		}
		logger.WithError(err).Error("P0 SSH Agent stopped with error")
		return err
	}

	logger.Info("P0 SSH Agent stopped")
	return nil
}
