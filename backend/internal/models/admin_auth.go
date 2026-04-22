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
