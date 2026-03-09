package scripts

type ProvisioningRequest struct {
	UserName     string `json:"userName"`
	Action       string `json:"action"`
	RequestID    string `json:"requestId"`
	PublicKey    string `json:"publicKey,omitempty"`
	CAPublicKey  string `json:"caPublicKey,omitempty"`
	Sudo         bool   `json:"sudo,omitempty"`
}

type ProvisioningResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
	Output  string `json:"output,omitempty"`
}

type Command string

const (
	CommandProvisionUser           Command = "provisionUser"
	CommandProvisionAuthorizedKeys Command = "provisionAuthorizedKeys"
	CommandProvisionCAKeys         Command = "provisionCAKeys"
	CommandProvisionSudo           Command = "provisionSudo"
	CommandProvisionSession        Command = "provisionSession"
	CommandRunAudit                Command = "runAudit"
)
