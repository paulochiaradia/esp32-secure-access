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
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
	TraceID string `json:"trace_id,omitempty"`
}

type HealthResponse struct {
	Status   string `json:"status"`
	Database string `json:"database"`
}

type SecurityHealthResponse struct {
	Status                  string `json:"status"`
	Database                string `json:"database"`
	ActiveAdminSessions     int64  `json:"active_admin_sessions"`
	RecentFailedAdminAuth   int64  `json:"recent_failed_admin_auth"`
	ExpiredRefreshSessions  int64  `json:"expired_refresh_sessions"`
	RecentFailedLoginWindow string `json:"recent_failed_login_window"`
}
