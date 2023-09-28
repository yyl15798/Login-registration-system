package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strings"
)

type User struct {
	gorm.Model
	Name       string `gorm:"varchar(20);not null"`
	Password   string `gorm:"size:255;not null"`
	Token      string `gorm:"size:255"`
	IsLoggedIn bool   `gorm:"default:false"`
}

func main() {

	//获取初始化的数据库
	db := InitDB()
	//延迟关闭数据库
	defer db.Close()
	//创建一个默认的路由引擎
	r := gin.Default()

	//注册
	r.POST("/register", func(ctx *gin.Context) {
		//获取参数
		name := ctx.PostForm("name")
		password := ctx.PostForm("password")

		//数据验证
		if len(name) == 0 {
			ctx.JSON(http.StatusUnprocessableEntity, gin.H{
				"message": "用户名不能为空",
			})
			return
		}

		var user User
		// 查询数据库，检查用户名是否已存在
		if err := db.Where("name = ?", name).First(&user).Error; err == nil {
			ctx.JSON(http.StatusUnprocessableEntity, gin.H{
				"message": "用户已存在",
			})
			return
		}

		//创建用户
		hasedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			ctx.JSON(http.StatusUnprocessableEntity, gin.H{
				"message": "密码加密错误",
			})
			return
		}
		token, err := generateToken() // 生成令牌
		newUser := User{
			Name:     name,
			Password: string(hasedPassword),
			Token:    token, // 存储令牌到数据库
		}
		db.Create(&newUser)

		//返回结果
		ctx.JSON(http.StatusOK, gin.H{
			"message": "注册成功",
		})
	})
	//登录
	r.POST("/login", func(ctx *gin.Context) {
		// 获取参数
		name := ctx.PostForm("name")
		password := ctx.PostForm("password")

		// 数据验证

		var user User
		// 查询数据库，检查用户是否存在
		if err := db.Where("name = ?", name).First(&user).Error; err != nil {
			ctx.JSON(http.StatusUnprocessableEntity, gin.H{
				"message": "用户不存在",
			})
			return
		}

		// 判断密码是否正确
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
			ctx.JSON(http.StatusUnprocessableEntity, gin.H{
				"message": "密码错误",
			})
			return
		}

		// 校验用户是否已经登录
		if user.IsLoggedIn {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"message": "用户已登录",
			})
			return
		}

		// 生成新的令牌
		token, err := generateToken()
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"message": "内部错误",
			})
			return
		}

		// 更新用户的令牌和登录状态
		db.Model(&user).Update(map[string]interface{}{
			"token":        token,
			"is_logged_in": true,
		})

		// 返回结果
		ctx.JSON(http.StatusOK, gin.H{
			"message": "登录成功",
			"name":    user.Name,
			"token":   token,
		})
	})
	//注销
	r.POST("/logout", func(ctx *gin.Context) {
		// 获取请求头部中的 Authorization 字段
		authorization := ctx.GetHeader("Authorization")

		// 检查授权是否为空
		if authorization == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"message": "未提供授权令牌",
			})
			return
		}

		// 检查授权令牌类型是否为 Bearer
		tokenParts := strings.Split(authorization, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"message": "无效的授权令牌",
			})
			return
		}

		// 提取令牌值
		token := tokenParts[1]

		var user User
		// 查询数据库，检查用户是否存在
		if err := db.Where("token = ?", token).First(&user).Error; err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"message": "未找到与令牌关联的用户",
			})
			return
		}

		// 更新用户的登录状态和令牌
		db.Model(&user).Update(map[string]interface{}{
			"is_logged_in": false,
			"token":        "",
		})

		ctx.JSON(http.StatusOK, gin.H{
			"message": "注销成功",
		})
	})
	//在9090端口启动服务
	panic(r.Run(":9090"))
}

func generateToken() (string, error) {
	// 生成一个 16 字节的随机数作为 token
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := hex.EncodeToString(tokenBytes)
	return token, nil
}

func InitDB() *gorm.DB {
	driverName := "mysql"
	host := "127.0.0.1"
	port := "3306"
	database := "test"
	username := "root"
	password := "1234"
	charset := "utf8"
	args := fmt.Sprintf("%s:%s@(%s:%s)/%s?charset=%s&parseTime=true",
		username,
		password,
		host,
		port,
		database,
		charset)

	db, err := gorm.Open(driverName, args)
	if err != nil {
		panic("failed to connect database, err:" + err.Error())
	}

	//迁移
	db.AutoMigrate(&User{})

	return db
}
