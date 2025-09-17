package main

import (
	"log"
	"github.com/you/authzsvc/internal/app"
	"github.com/you/authzsvc/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil { 
		log.Fatalf("config: %v", err) 
	}
	if err := app.Run(cfg); err != nil { 
		log.Fatalf("app: %v", err) 
	}
}