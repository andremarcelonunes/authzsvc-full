package handlers

import (
	"net/http"
	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
)

type PolicyHandlers struct{ E *casbin.Enforcer }

type policyReq struct{ Sub, Obj, Act string }

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
	ok, err := h.E.AddPolicy(r.Sub, r.Obj, r.Act)
	if err != nil || !ok { c.JSON(http.StatusBadRequest, gin.H{"error": "not added"}); return }
	_ = h.E.SavePolicy(); c.Status(http.StatusNoContent)
}

func (h *PolicyHandlers) Remove(c *gin.Context) {
	var r policyReq
	if err := c.ShouldBindJSON(&r); err != nil { c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return }
	ok, err := h.E.RemovePolicy(r.Sub, r.Obj, r.Act)
	if err != nil || !ok { c.JSON(http.StatusBadRequest, gin.H{"error": "not removed"}); return }
	_ = h.E.SavePolicy(); c.Status(http.StatusNoContent)
}
