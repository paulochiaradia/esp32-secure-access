package models

// AdminLoginRequest recebe as credenciais do administrador.
type AdminLoginRequest struct {
	Username string `json:"username" binding:"required,min=3,max=100"`
	Password string `json:"password" binding:"required,min=8,max=128"`
}

// AdminRefreshRequest recebe o refresh token atual para renovacao da sessao.
type AdminRefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// AdminLogoutRequest recebe o refresh token a ser invalidado no logout.
type AdminLogoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// AdminBootstrapRequest cria o primeiro administrador do sistema.
type AdminBootstrapRequest struct {
	Username string `json:"username" binding:"required,min=3,max=100"`
	Password string `json:"password" binding:"required,min=8,max=128"`
	Role     string `json:"role"`
}

// AdminChangePasswordRequest altera senha e revoga sessões ativas.
type AdminChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required,min=8,max=128"`
	NewPassword     string `json:"new_password" binding:"required,min=8,max=128"`
}

// AdminRevokeSessionsRequest permite revogar sessões de um usuário alvo.
type AdminRevokeSessionsRequest struct {
	UserID *uint `json:"user_id"`
}

// AdminUserInfo representa os dados publicos do administrador autenticado.
type AdminUserInfo struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

// AdminLoginResponse retorna os tokens emitidos para a sessao administrativa.
type AdminLoginResponse struct {
	AccessToken      string        `json:"access_token"`
	TokenType        string        `json:"token_type"`
	ExpiresIn        int64         `json:"expires_in"`
	RefreshToken     string        `json:"refresh_token"`
	RefreshExpiresIn int64         `json:"refresh_expires_in"`
	User             AdminUserInfo `json:"user"`
}
