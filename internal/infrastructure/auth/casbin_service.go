package auth

import (
	"github.com/casbin/casbin/v2"
	"github.com/casbin/gorm-adapter/v3"
	"gorm.io/gorm"
)

type CasbinService struct{ E *casbin.Enforcer }

func NewCasbinService(db *gorm.DB, modelPath string) (*CasbinService, error) {
	adp, err := gormadapter.NewAdapterByDB(db)
	if err != nil { return nil, err }
	E, err := casbin.NewEnforcer(modelPath, adp)
	if err != nil { return nil, err }
	if err := E.LoadPolicy(); err != nil { return nil, err }
	return &CasbinService{E}, nil
}