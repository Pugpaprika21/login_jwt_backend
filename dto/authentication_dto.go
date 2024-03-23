package dto

type LoginBodyRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterBodyRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

type AuthenticationRespones struct {
	UserID   int32  `json:"userId"`
	Username string `json:"username"`
	Password string `json:"password"`
	TokenJWT string `json:"tokenJWT"`
}
