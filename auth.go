package main

import (
	"log"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
)

var (
	logger                = log.New(os.Stdout, "[GATEWAY][AUTH]", 0)
	jwtSecret             = []byte(os.Getenv("JWT_SECRET"))
	AccessTokenCookieName = "token"
)

func CreateJWTToken(userId int64) (string, error) {
	claims := jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Hour * 24 * 30).Unix(),
		Issuer:    os.Getenv("JWT_ISSUER"),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["userID"] = userId
	key, err := token.SignedString(jwtSecret)
	if err != nil {
		logger.Printf("ERROR: Couldn't generate JWT token: %s", err)
		return "", err
	}
	return key, nil

}

func GetUserId(token string) (int64, error) {
	user, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return 0, err
	}
	userID := user.Header["userID"].(int64)
	return userID, nil
}

func RequireLogin(request *fiber.Ctx) (int64, error) {
	token := request.Get(AccessTokenCookieName, "")
	userId, err := GetUserId(token)
	if err != nil {
		return 0, err
	}
	return userId, nil
}
