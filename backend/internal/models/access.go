package models

type AccessRequest struct {
	UID       string `json:"uid" binding:"required"`
	Timestamp int64  `json:"timestamp" binding:"required"`
	Nonce     string `json:"nonce" binding:"required"`
	Signature string `json:"signature" binding:"required"`
}

type AccessResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	User    string `json:"user,omitempty"`
}

type ErrorResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type HealthResponse struct {
	Status   string `json:"status"`
	Database string `json:"database"`
}
