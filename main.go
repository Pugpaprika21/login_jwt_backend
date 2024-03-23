package main

import (
	"log"
	"os"

	"github.com/Pugpaprika21/database"
	"github.com/Pugpaprika21/handle"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"gorm.io/gorm"
)

func init() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func setupRouter(e *echo.Echo, db *gorm.DB) {
	authentication := handle.NewAuthentication(db)
	e.POST("/api/login", authentication.Login)
	e.POST("/api/register", authentication.Register)
	e.POST("/api/jwt_protected", authentication.JWTProtected)
}

func main() {
	conf := database.New()
	conf.Host = os.Getenv("DB_HOST")
	conf.Username = os.Getenv("DB_USERNAME")
	conf.Password = os.Getenv("DB_PASSWORD")
	conf.DBname = os.Getenv("DB_NAME")
	conf.Port = os.Getenv("DB_PORT")
	conf.SSLMode = os.Getenv("DB_SSLMODE")
	conf.TimeZone = os.Getenv("DB_TIMEZONE")

	db, err := conf.Setup()
	if err != nil {
		log.Fatal("Cannot connect to database:", err)
	}

	e := echo.New()
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	setupRouter(e, db)

	e.Start(os.Getenv("PORT"))
}
