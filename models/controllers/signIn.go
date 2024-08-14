package controllers

import (
	"auth-test/models/auth"
	"auth-test/models/user"
	"html/template"
	"io"
	"net/http"

	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

type Templates struct {
	templates *template.Template
}

func (t *Templates) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func NewTemplates() *Templates {
	t := new(Templates)
	t.templates = template.Must(template.ParseGlob("templates/*.html"))
	return t
}

func SignInForm() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.Render(http.StatusOK, "index", nil)
	}
}

func SignIn() echo.HandlerFunc {
	return func(c echo.Context) error {
		storedUser := user.LoadTestUser()
		u := new(user.User)
		if err := c.Bind(u); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		if err := bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(u.Password)); err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "Password is incorrect")
		}
		err := auth.GenerateTokensAndSetCookies(storedUser, c)

		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "Token is incorrect")
		}

		return c.Redirect(http.StatusMovedPermanently, "/admin")
	}
}
