package main

import (
	"fmt"
	"learning-go/cmd/handlers"
	"learning-go/internal/middleware"
	"learning-go/internal/utils"
	"net/http"
)


func handleProtected(w http.ResponseWriter, req *http.Request){
	claims, ok := req.Context().Value(middleware.UserContextKey).(*utils.CustomClaims)
	if !ok {
		http.Error(w, "Unautorized",http.StatusUnauthorized)
		return
	}
	w.Write(fmt.Appendf(nil, "Welcome back userId %d", claims.UserId))
}



func main() {
	utils.InitRedis()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/login", handlers.HandleLogin)
	mux.HandleFunc("GET /api/v1/me", handleProtected)
	mux.HandleFunc("POST /api/v1/refresh", handlers.RefreshTokenHandler)
	mux.HandleFunc("POST /api/v1/login/otp", handlers.RequestOTPHandler)
	mux.HandleFunc("POST /api/v1/login/otp/validate", handlers.ValidateOTPHandler)
	fmt.Println("Listening on localhost:8080")
	if err := http.ListenAndServe(":8080", mux); err != nil{
		panic(err)
	}
}
