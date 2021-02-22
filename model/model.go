package model

import "github.com/dgrijalva/jwt-go"

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

type Claims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}
