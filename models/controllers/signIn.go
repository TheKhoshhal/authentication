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

type FormData struct {
	Error map[string]string
}

func NewFormData() *FormData {
	f := new(FormData)
	f.Error = make(map[string]string)
	return f
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

		if u.Name != storedUser.Name {
			formData := FormData{
				Error: map[string]string{"value": "UserName not found", "username": ""},
			}
			return c.Render(http.StatusUnauthorized, "signin", formData)
		}

		if err := bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(u.Password)); err != nil {
			formData := FormData{
				Error: map[string]string{"value": "Password is incorrect", "username": u.Name},
			}
			return c.Render(http.StatusUnauthorized, "signin", formData)
		}
		err := auth.GenerateTokensAndSetCookies(storedUser, c)

		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "Token is incorrect")
		}

		// formData := NewFormData()

		return c.Redirect(http.StatusMovedPermanently, "/admin")
	}
}
