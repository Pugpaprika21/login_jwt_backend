package database

import (
	"fmt"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type config struct {
	Host     string
	Username string
	Password string
	DBname   string
	Port     string
	SSLMode  string
	TimeZone string
}

func New() *config {
	return &config{}
}

func (c *config) Setup() (*gorm.DB, error) {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=%s",
		c.Host, c.Username, c.Password, c.DBname, c.Port, c.SSLMode, c.TimeZone)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	return db, nil
}
