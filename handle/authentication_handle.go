package handle

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Pugpaprika21/dto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type authentication struct {
	query        *gorm.DB
	jwtSecretKey []byte
}

func NewAuthentication(db *gorm.DB) *authentication {
	return &authentication{
		query:        db,
		jwtSecretKey: []byte(os.Getenv("SECRET_KEY")),
	}
}

func (a *authentication) Login(c echo.Context) error {
	var body *dto.LoginBodyRequest
	var result []map[string]any
	if err := c.Bind(&body); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"massage": err.Error()})
	}

	a.query.Table("users").Where("username = ?", body.Username).Find(&result)
	if len(result) == 0 {
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "username invalid"})
	}

	if !a.checkPasswordHash(body.Password, result[0]["password"].(string)) {
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "password invalid"})
	}

	jwt, _ := a.genJWTTokenString(result)

	return c.JSON(http.StatusOK, echo.Map{"message": "login success", "data": dto.AuthenticationRespones{
		UserID:   result[0]["id"].(int32),
		Username: result[0]["username"].(string),
		Password: result[0]["password"].(string),
		TokenJWT: jwt,
	}})
}

func (a *authentication) Register(c echo.Context) error {
	var body *dto.RegisterBodyRequest
	var result []map[string]any
	if err := c.Bind(&body); err != nil {
		return c.JSON(http.StatusBadRequest, echo.Map{"massage!!": err.Error()})
	}

	a.query.Table("users").Where("username = ?", body.Username).Find(&result)
	if len(result) > 0 {
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": "username is exiting"})
	}

	hash, _ := a.hashPassword(body.Password)

	data := map[string]any{}
	data["username"] = body.Username
	data["password"] = hash
	data["email"] = body.Email
	if err := a.query.Table("users").Create(data).Error; err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"message": err.Error()})
	}

	return c.JSON(http.StatusOK, echo.Map{"body": body})
}

func (a *authentication) JWTProtected(c echo.Context) error {
	authHeader := c.Request().Header.Get("Authorization")

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "Invalid Authorization Header Format"})
	}

	bearerToken := authHeader[7:]
	token, err := jwt.Parse(bearerToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(a.jwtSecretKey), nil
	})

	switch {
	case err != nil && err == jwt.ErrSignatureInvalid:
		return c.JSON(http.StatusUnauthorized, echo.Map{"message": "Invalid Token"})
	case err != nil:
		return c.JSON(http.StatusBadRequest, echo.Map{"message": "Expired Token"})
	case !token.Valid:
		return c.JSON(http.StatusUnauthorized, echo.Map{"message": "Invalid Token"})
	}

	claims, _ := token.Claims.(jwt.MapClaims)
	responseData := echo.Map{"message": "success", "data": claims}

	return c.JSON(http.StatusOK, responseData)
}

func (a *authentication) genJWTTokenString(data any) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"data": data,
		"exp":  time.Now().Add(time.Minute).Unix(),
	})

	jwt, err := token.SignedString(a.jwtSecretKey)
	if err != nil {
		return err.Error(), err
	}
	return jwt, nil
}

func (a *authentication) hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func (a *authentication) checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
