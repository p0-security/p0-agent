package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"

	"p0-ssh-agent/internal/backoff"
	"p0-ssh-agent/internal/jwt"
	"p0-ssh-agent/internal/rpc"
	"p0-ssh-agent/scripts"
	"p0-ssh-agent/types"
)

// AuthenticationError represents an authentication failure that should cause immediate exit
type AuthenticationError struct {
	StatusCode int
	Message    string
}

func (e *AuthenticationError) Error() string {
	return e.Message
}

const (
	DefaultBackoffStart   = 1 * time.Second
	DefaultBackoffMax     = 30 * time.Second
)

type Client struct {
	config     *types.Config
	logger     *logrus.Logger
	jwtManager *jwt.Manager
	rpcClient  *rpc.Client
	backoff    *backoff.Backoff

	conn          *websocket.Conn
	connMu        sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	connected     chan struct{}
	isShutdown    bool
	shutdownMu    sync.RWMutex
	heartbeatStop chan struct{}
	lastHeartbeat time.Time
	heartbeatMu   sync.RWMutex
	reconnecting  bool
	reconnectMu   sync.Mutex
}

func New(config *types.Config, logger *logrus.Logger) (*Client, error) {
	jwtManager := jwt.NewManager(logger)
	if err := jwtManager.LoadKey(config.KeyPath); err != nil {
		return nil, fmt.Errorf("failed to load JWT key: %w", err)
	}

	backoffInstance, err := backoff.New(DefaultBackoffStart, DefaultBackoffMax)
	if err != nil {
		return nil, fmt.Errorf("failed to create backoff: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	client := &Client{
		config:        config,
		logger:        logger,
		jwtManager:    jwtManager,
		backoff:       backoffInstance,
		ctx:           ctx,
		cancel:        cancel,
		connected:     make(chan struct{}),
		heartbeatStop: make(chan struct{}),
	}

	client.rpcClient = rpc.NewClient()

	client.rpcClient.AddMethod("call", client.handleCallMethod)

	client.rpcClient.SetOnConnected(func() {
		client.logger.Info("WebSocket connection established, sending setClientId")
		if _, err := client.rpcClient.Call("setClientId", types.SetClientIDRequest{
			ClientID: client.config.GetClientID(),
		}); err != nil {
			client.logger.WithError(err).Error("Failed to set client ID - triggering reconnection")
			client.forceReconnect()
			return
		}
		client.logger.Info("Client ID set successfully")

		client.heartbeatMu.Lock()
		client.lastHeartbeat = time.Now()
		client.heartbeatMu.Unlock()

		go client.startHeartbeat()

		select {
		case client.connected <- struct{}{}:
		default:
		}
	})

	return client, nil
}

func (c *Client) Connect() error {
	return c.connect()
}

func (c *Client) connect() error {
	for {
		c.shutdownMu.RLock()
		if c.isShutdown {
			c.shutdownMu.RUnlock()
			return fmt.Errorf("client is shutdown")
		}
		c.shutdownMu.RUnlock()

		if err := c.connectOnce(); err != nil {
			// Check if this is an authentication error - exit immediately
			if authErr, ok := err.(*AuthenticationError); ok {
				c.logger.WithFields(logrus.Fields{
					"status_code": authErr.StatusCode,
					"error":       authErr.Message,
				}).Error("💀 Authentication failed - exiting for systemd restart management")
				return authErr
			}

			c.logger.WithError(err).Warn("Connection failed, retrying...")

			select {
			case <-c.ctx.Done():
				return c.ctx.Err()
			case <-time.After(c.backoff.Next()):
				continue
			}
		}

		c.backoff.Reset()
		return nil
	}
}

func (c *Client) connectOnce() error {
	token, err := c.jwtManager.CreateJWT(c.config.GetClientID())
	if err != nil {
		return fmt.Errorf("failed to create JWT: %w", err)
	}

	tunnelURL := c.config.TunnelHost
	if tunnelURL == "" {
		return fmt.Errorf("tunnel host URL not configured")
	}

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+token)

	c.logger.WithFields(logrus.Fields{
		"url":     tunnelURL,
		"headers": map[string]string{"Authorization": "Bearer <redacted>"},
	}).Debug("Attempting WebSocket connection")

	conn, resp, err := websocket.DefaultDialer.Dial(tunnelURL, headers)
	if err != nil {
		if resp != nil {
			c.logger.WithFields(logrus.Fields{
				"status_code": resp.StatusCode,
				"status":      resp.Status,
				"headers":     resp.Header,
			}).Error("WebSocket handshake failed with HTTP response")

			if resp.StatusCode == 401 {
				c.logger.Error("🔐 Authentication failed - JWT token rejected by server")
				c.logger.Error("💡 Check: 1) Client ID is registered 2) JWT key is correct 3) Token not expired")
				c.logger.Error("💀 Exiting to let systemd handle restart rate limiting")
				
				return &AuthenticationError{
					StatusCode: 401,
					Message:    "authentication failed - JWT token rejected by server",
				}
			} else if resp.StatusCode == 403 {
				c.logger.Error("🚫 Forbidden - Client ID may not be authorized")
				c.logger.Error("💡 Check: Client ID is registered and authorized for this environment")
				c.logger.Error("💀 Exiting to let systemd handle restart rate limiting")
				
				return &AuthenticationError{
					StatusCode: 403,
					Message:    "forbidden - client ID may not be authorized",
				}
			} else if resp.StatusCode == 404 {
				c.logger.Error("🔍 Not Found - Check WebSocket endpoint path")
			}

			return fmt.Errorf("WebSocket handshake failed: HTTP %d %s", resp.StatusCode, resp.Status)
		}

		return fmt.Errorf("failed to dial WebSocket: %w", err)
	}

	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()

	c.logger.Info("WebSocket connection established, connecting JSON-RPC client")

	if err := c.rpcClient.ConnectWebSocketWithContext(c.ctx, conn); err != nil {
		conn.Close()
		return fmt.Errorf("failed to connect JSON-RPC client: %w", err)
	}

	return nil
}

func (c *Client) handleCallMethod(ctx context.Context, params json.RawMessage) (interface{}, error) {
	c.logger.Info("🔄 Received 'call' method - processing provisioning request")

	var request types.ForwardedRequest
	if err := json.Unmarshal(params, &request); err != nil {
		c.logger.WithError(err).Error("Failed to unmarshal params to ForwardedRequest")
		return nil, fmt.Errorf("failed to unmarshal ForwardedRequest: %w", err)
	}

	logHeaders := make(map[string]interface{})
	for key, value := range request.Headers {
		if strings.ToLower(key) != "authorization" {
			logHeaders[key] = value
		}
	}

	c.logger.WithFields(logrus.Fields{
		"method":    request.Method,
		"path":      request.Path,
		"headers":   logHeaders,
		"params":    request.Params,
		"data":      request.Data,
		"client_id": c.config.GetClientID(),
		"has_data":  request.Data != nil,
		"dry_run":   c.config.DryRun,
	}).Info("📥 P0 SSH Agent received provisioning request")

	var scriptResult scripts.ProvisioningResult
	var command string

	if request.Data != nil {
		if dataMap, ok := request.Data.(map[string]interface{}); ok {
			if cmdValue, exists := dataMap["command"]; exists {
				if cmdStr, ok := cmdValue.(string); ok {
					command = cmdStr
				}
			}
		}
	}

	if command != "" && request.Data != nil {
		scriptResult = scripts.ExecuteScript(command, request.Data, c.config.DryRun, c.logger)
	} else {
		scriptResult = scripts.ProvisioningResult{
			Success: true,
			Message: "Request logged - no command specified",
		}
	}

	response := types.ForwardedResponse{
		Headers:    map[string]interface{}{"content-type": "application/json"},
		Status:     200,
		StatusText: "OK",
	}

	if scriptResult.Success {
		data := map[string]interface{}{
			"success":   true,
			"message":   scriptResult.Message,
			"client_id": c.config.GetClientID(),
			"command":   command,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"status":    "completed",
		}
		if scriptResult.Output != "" {
			data["output"] = scriptResult.Output
		}
		response.Data = data
		c.logger.WithFields(logrus.Fields{
			"command": command,
			"message": scriptResult.Message,
		}).Info("✅ Script executed successfully")
	} else {
		response.Status = 500
		response.StatusText = "Internal Server Error"
		response.Data = map[string]interface{}{
			"success":   false,
			"error":     scriptResult.Error,
			"client_id": c.config.GetClientID(),
			"command":   command,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"status":    "failed",
		}
		c.logger.WithFields(logrus.Fields{
			"command": command,
			"error":   scriptResult.Error,
		}).Error("❌ Script execution failed")
	}

	c.logger.WithFields(logrus.Fields{
		"status":      response.Status,
		"status_text": response.StatusText,
		"command":     command,
	}).Info("📤 P0 SSH Agent sending response")

	return response, nil
}

func (c *Client) WaitUntilConnected() error {
	return c.rpcClient.WaitUntilConnected()
}

func (c *Client) Run() error {
	if err := c.Connect(); err != nil {
		return err
	}

	<-c.ctx.Done()
	return c.ctx.Err()
}

func (c *Client) Shutdown() {
	c.shutdownMu.Lock()
	c.isShutdown = true
	c.shutdownMu.Unlock()

	close(c.heartbeatStop)
	c.cancel()

	if err := c.rpcClient.Close(); err != nil {
		c.logger.WithError(err).Warn("Error closing RPC client")
	}

	c.logger.Info("Client shutdown completed")
}

func (c *Client) startHeartbeat() {
	heartbeatInterval := c.config.GetHeartbeatInterval()
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	c.logger.WithField("interval", heartbeatInterval).Info("🫀 Starting heartbeat monitor")

	for {
		select {
		case <-ticker.C:
			if err := c.sendHeartbeat(); err != nil {
				c.logger.WithError(err).Error("💔 Heartbeat failed - connection may be lost")
				c.forceReconnect()
				return
			}
		case <-c.heartbeatStop:
			c.logger.Info("🫀 Heartbeat monitor stopped")
			return
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Client) sendHeartbeat() error {
	c.logger.Debug("🫀 Sending heartbeat (setClientId)")

	start := time.Now()
	_, err := c.rpcClient.Call("setClientId", types.SetClientIDRequest{
		ClientID: c.config.GetClientID(),
	})

	if err != nil {
		duration := time.Since(start)
		c.logger.WithFields(logrus.Fields{
			"error":    err.Error(),
			"duration": duration,
		}).Error("🚨 Heartbeat call failed")
		return err
	}

	c.heartbeatMu.Lock()
	c.lastHeartbeat = time.Now()
	c.heartbeatMu.Unlock()

	duration := time.Since(start)
	c.logger.WithFields(logrus.Fields{
		"duration":  duration,
		"client_id": c.config.GetClientID(),
		"timestamp": c.lastHeartbeat.Format(time.RFC3339),
	}).Info("💚 Heartbeat successful")

	return nil
}

func (c *Client) resetContext() {
	c.cancel()
	c.ctx, c.cancel = context.WithCancel(context.Background())
}

func (c *Client) forceReconnect() {
	c.reconnectMu.Lock()
	if c.reconnecting {
		c.reconnectMu.Unlock()
		c.logger.Debug("🔄 Reconnection already in progress, skipping")
		return
	}

	c.reconnecting = true
	c.reconnectMu.Unlock()

	c.logger.Warn("🔄 Forcing reconnection due to connection failure")

	close(c.heartbeatStop)
	c.heartbeatStop = make(chan struct{})

	c.connMu.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connMu.Unlock()

	if err := c.rpcClient.Close(); err != nil {
		c.logger.WithError(err).Debug("Error closing RPC client during reconnect")
	}

	c.resetContext()

	go func() {
		defer func() {
			c.reconnectMu.Lock()
			c.reconnecting = false
			c.reconnectMu.Unlock()
		}()

		c.logger.Info("🔄 Starting reconnection process")
		if err := c.Connect(); err != nil {
			c.logger.WithError(err).Error("❌ Reconnection failed")
		}
	}()
}


func (c *Client) GetLastHeartbeat() time.Time {
	c.heartbeatMu.RLock()
	defer c.heartbeatMu.RUnlock()
	return c.lastHeartbeat
}

func (c *Client) IsConnectionHealthy() bool {
	c.heartbeatMu.RLock()
	lastHeartbeat := c.lastHeartbeat
	c.heartbeatMu.RUnlock()

	if lastHeartbeat.IsZero() {
		return false
	}

	timeSinceLastHeartbeat := time.Since(lastHeartbeat)
	maxAllowedGap := c.config.GetHeartbeatInterval() * 2

	healthy := timeSinceLastHeartbeat < maxAllowedGap

	if !healthy {
		c.logger.WithFields(logrus.Fields{
			"last_heartbeat":     lastHeartbeat.Format(time.RFC3339),
			"time_since":         timeSinceLastHeartbeat,
			"max_allowed_gap":    maxAllowedGap,
			"connection_healthy": healthy,
		}).Warn("⚠️ Connection health check failed")
	}

	return healthy
}

