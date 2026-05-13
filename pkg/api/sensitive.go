package api

import (
	"Rshell/pkg/database"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

type SensitiveResultResp struct {
	Id         int64  `json:"id"`
	Uid        string `json:"uid"`
	SearchPath string `json:"searchPath"`
	Content    string `json:"content"`
	CreatedAt  int64  `json:"createdAt"`
}

func ListSensitiveResults(c *gin.Context) {
	uid := c.Param("uid")
	if uid == "" {
		c.JSON(http.StatusOK, gin.H{"status": 400, "data": "uid is required"})
		return
	}

	var results []database.SensitiveResults
	database.Engine.Where("uid = ?", uid).Desc("id").Find(&results)

	var resp []SensitiveResultResp
	for _, r := range results {
		resp = append(resp, SensitiveResultResp{
			Id:         r.Id,
			Uid:        r.Uid,
			SearchPath: r.SearchPath,
			Content:    r.Content,
			CreatedAt:  r.CreatedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "data": resp})
}

func GetSensitiveResultContent(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": 400, "data": "invalid id"})
		return
	}

	var result database.SensitiveResults
	has, err := database.Engine.ID(id).Get(&result)
	if err != nil || !has {
		c.JSON(http.StatusOK, gin.H{"status": 404, "data": "result not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "data": result.Content})
}

func DeleteSensitiveResult(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": 400, "data": "invalid id"})
		return
	}

	_, err = database.Engine.ID(id).Delete(&database.SensitiveResults{})
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": 500, "data": "delete failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK})
}

func CleanSensitiveResults(c *gin.Context) {
	uid := c.Param("uid")
	if uid == "" {
		c.JSON(http.StatusOK, gin.H{"status": 400, "data": "uid is required"})
		return
	}

	// 删除24小时前的记录（自动清理过期数据）
	cutoff := time.Now().Add(-24 * time.Hour).Unix()
	database.Engine.Where("uid = ? AND created_at < ?", uid, cutoff).Delete(&database.SensitiveResults{})

	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK})
}
