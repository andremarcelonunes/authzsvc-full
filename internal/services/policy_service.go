package services

import (
	"github.com/casbin/casbin/v2"
	"github.com/you/authzsvc/domain"
)

// CasbinEnforcerWrapper wraps the real Casbin enforcer to implement our interface
type CasbinEnforcerWrapper struct {
	enforcer *casbin.Enforcer
}

// NewCasbinEnforcerWrapper creates a wrapper for the real Casbin enforcer
func NewCasbinEnforcerWrapper(enforcer *casbin.Enforcer) domain.CasbinEnforcer {
	return &CasbinEnforcerWrapper{enforcer: enforcer}
}

func (w *CasbinEnforcerWrapper) AddPolicy(params ...interface{}) (bool, error) {
	return w.enforcer.AddPolicy(params...)
}

func (w *CasbinEnforcerWrapper) RemovePolicy(params ...interface{}) (bool, error) {
	return w.enforcer.RemovePolicy(params...)
}

func (w *CasbinEnforcerWrapper) Enforce(rvals ...interface{}) (bool, error) {
	return w.enforcer.Enforce(rvals...)
}

func (w *CasbinEnforcerWrapper) GetPolicy() ([][]string, error) {
	return w.enforcer.GetPolicy()
}

func (w *CasbinEnforcerWrapper) SavePolicy() error {
	return w.enforcer.SavePolicy()
}

// PolicyServiceImpl implements domain.PolicyService using Casbin
type PolicyServiceImpl struct {
	enforcer domain.CasbinEnforcer
}

// NewPolicyService creates a new policy service
func NewPolicyService(enforcer *casbin.Enforcer) domain.PolicyService {
	return &PolicyServiceImpl{
		enforcer: NewCasbinEnforcerWrapper(enforcer),
	}
}

// NewPolicyServiceWithEnforcer creates a new policy service with a CasbinEnforcer interface (for testing)
func NewPolicyServiceWithEnforcer(enforcer domain.CasbinEnforcer) domain.PolicyService {
	return &PolicyServiceImpl{
		enforcer: enforcer,
	}
}

// AddPolicy implements domain.PolicyService
func (p *PolicyServiceImpl) AddPolicy(role, resource, action string) error {
	_, err := p.enforcer.AddPolicy(role, resource, action)
	if err != nil {
		return err
	}
	return p.enforcer.SavePolicy()
}

// RemovePolicy implements domain.PolicyService
func (p *PolicyServiceImpl) RemovePolicy(role, resource, action string) error {
	_, err := p.enforcer.RemovePolicy(role, resource, action)
	if err != nil {
		return err
	}
	return p.enforcer.SavePolicy()
}

// CheckPermission implements domain.PolicyService
func (p *PolicyServiceImpl) CheckPermission(role, resource, action string) (bool, error) {
	return p.enforcer.Enforce(role, resource, action)
}

// GetPolicies implements domain.PolicyService
func (p *PolicyServiceImpl) GetPolicies() [][]string {
	policies, _ := p.enforcer.GetPolicy()
	return policies
}