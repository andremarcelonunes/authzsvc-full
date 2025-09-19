package handlers

import (
	"net/http"
	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
)

type PolicyHandlers struct{ E *casbin.Enforcer }

type policyReq struct{ 
	Sub  string `json:"subject" binding:"required"`
	Obj  string `json:"object" binding:"required"`
	Act  string `json:"action" binding:"required"`
	Rule string `json:"rule,omitempty"` // Optional 4th parameter for field validation
}

func (h *PolicyHandlers) List(c *gin.Context) { 
	policies, err := h.E.GetPolicy()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, policies) 
}

func (h *PolicyHandlers) Add(c *gin.Context) {
	var r policyReq
	if err := c.ShouldBindJSON(&r); err != nil { c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return }
	
	// Additional validation to prevent blank policies
	if r.Sub == "" || r.Obj == "" || r.Act == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "subject, object, and action cannot be empty"})
		return
	}
	
	var ok bool
	var err error
	if r.Rule != "" {
		// Add 4-parameter policy with validation rule
		ok, err = h.E.AddPolicy(r.Sub, r.Obj, r.Act, r.Rule)
	} else {
		// Add standard 3-parameter policy
		ok, err = h.E.AddPolicy(r.Sub, r.Obj, r.Act)
	}
	
	if err != nil || !ok { c.JSON(http.StatusBadRequest, gin.H{"error": "not added"}); return }
	_ = h.E.SavePolicy(); c.Status(http.StatusNoContent)
}

func (h *PolicyHandlers) Remove(c *gin.Context) {
	var r policyReq
	if err := c.ShouldBindJSON(&r); err != nil { c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return }
	
	// Additional validation to prevent blank policy removal attempts
	if r.Sub == "" || r.Obj == "" || r.Act == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "subject, object, and action cannot be empty"})
		return
	}
	
	var ok bool
	var err error
	if r.Rule != "" {
		// Remove 4-parameter policy with validation rule
		ok, err = h.E.RemovePolicy(r.Sub, r.Obj, r.Act, r.Rule)
	} else {
		// Remove standard 3-parameter policy
		ok, err = h.E.RemovePolicy(r.Sub, r.Obj, r.Act)
	}
	
	if err != nil || !ok { c.JSON(http.StatusBadRequest, gin.H{"error": "not removed"}); return }
	_ = h.E.SavePolicy(); c.Status(http.StatusNoContent)
}
