package handlers

import (
	"brick/ledger"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// QueryBlockchain queries data from the ledger
func QueryBlockchain(c *gin.Context) {
	key := c.Query("key")
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "key parameter is required",
		})
		return
	}

	svc := ledger.Get()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Ledger service not initialized",
		})
		return
	}

	value, err := svc.QueryState(key)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"key":     key,
		"value":   value,
		"ledger":  svc.Mode(),
		"message": "Query executed successfully",
	})
}

// InvokeChaincode invokes a ledger function
func InvokeChaincode(c *gin.Context) {
	var request map[string]interface{}
	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	function, _ := request["function"].(string)
	if function == "" {
		function = "CreateAsset"
	}

	svc := ledger.Get()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Ledger service not initialized",
		})
		return
	}

	result, err := svc.Invoke(function, request)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":        true,
		"transaction_id": fmt.Sprintf("tx_%d", time.Now().UnixNano()),
		"message":        "Chaincode invoked successfully",
		"data":           result,
		"ledger":         svc.Mode(),
	})
}

// GetHistory retrieves transaction history for a key
func GetHistory(c *gin.Context) {
	key := c.Param("key")

	svc := ledger.Get()
	if svc == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Ledger service not initialized",
		})
		return
	}

	history, err := svc.GetHistory(key)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"key":     key,
		"history": history,
		"ledger":  svc.Mode(),
	})
}
