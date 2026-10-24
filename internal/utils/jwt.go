package utils

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

type CustomClaims struct {
	UserId    int    `json:"user_id"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

func GenerateAccessToken(userId int) (string, error) {
	accessClaims := CustomClaims{
		UserId:    userId,
		TokenType: "access",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		Issuer:    "go-service",
	}
	accessToken, err := signToken(accessClaims)
	if err != nil {
		return "", err
	}
	return accessToken, nil
}

func GenerateRefreshToken(userId int) (string, error) {

	refreshClaims := CustomClaims{
		UserId:    userId,
		TokenType: "refresh",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Minute)),
		Issuer:    "go-service",
	}
	refreshToken, err := signToken(refreshClaims)
	if err != nil {
		return "", err
	}
	return refreshToken, nil
}

func signToken(claims CustomClaims) (string, error) {
	accessTokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	secretKey, err := getSecretKey()
	if err != nil{
		return "", err
	}
	accessToken, err := accessTokenObj.SignedString(secretKey)
	if err != nil {
		return "", err
	}
	return accessToken, nil
}

func getSecretKey() ([]byte, error) {
	err := godotenv.Load()
	if err != nil {
		return nil, err
	}
	return []byte(os.Getenv("SECRET_JWT_KEY")), nil
}

func InitDotEnv() {
	err := godotenv.Load()
	if err != nil {
		panic(err)
	}
}

func ExtractToken(tokenStr string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		secretKey , err := getSecretKey()
		if err != nil{
			return nil , err
		}
		return secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, errors.New("Invalid token claims")
	}

	return claims, nil
}
