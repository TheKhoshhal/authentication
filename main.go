package main

import (
	"net/http"

	"auth-test/models/auth"
	"auth-test/models/controllers"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	e := echo.New()

	e.Use(middleware.Logger())

	e.GET("/", func(ctx echo.Context) error {
		return ctx.String(http.StatusOK, "Accessible")
	})

	e.Renderer = controllers.NewTemplates()

	e.GET("/user/signin", controllers.SignInForm()).Name = "userSignInForm"
	e.POST("/user/signin", controllers.SignIn())

	adminGroup := e.Group("/admin")
	adminGroup.Use(middleware.JWTWithConfig(middleware.JWTConfig{
		Claims:                  &auth.Claims{},
		SigningKey:              []byte(auth.GetJWTSecret()),
		TokenLookup:             "cookie:access-token",
		ErrorHandlerWithContext: auth.JWTErrorChecker,
	}))

	adminGroup.Use(auth.TokenRefresherMiddleware)

	adminGroup.GET("", controllers.Admin())

	e.Logger.Fatal(e.Start(":8777"))
}
