package handlers

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"learning-go/internal/utils"
	"math/big"
	"net/http"
	"time"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type AuthenticationResponse struct {
	AccessToken string `json:"access_token"`
}

type OTPRequest struct {
	Email string `json:"email"`
}

type ValidateOTPRequest struct {
	OTP   string `json:"otp"`
	Email string `json:"email"`
}

func HandleLogin(w http.ResponseWriter, req *http.Request) {
	var request LoginRequest

	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if request.Email != "abdaladarwesh63@gmail.com" || request.Password != "123" {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	accessToken, refreshToken, err := generateTokens(1)

	if err != nil {
		http.Error(w, "Internal server error : error creating the token"+err.Error(), http.StatusInternalServerError)
		return
	}

	var cookie http.Cookie
	createRefreshCookie(&refreshToken, &cookie)

	http.SetCookie(w, &cookie)

	authResponse := AuthenticationResponse{
		AccessToken: accessToken,
	}
	response, err := json.Marshal(authResponse)
	if err != nil {
		http.Error(w, "Error in creating the response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(response)
}

func createRefreshCookie(refreshToken *string, cookie *http.Cookie) {
	*cookie = http.Cookie{
		Name:     "refresh_token",
		Value:    *refreshToken,
		Path:     "api/v1/refresh",
		MaxAge:   86400 * 7,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
	}
}

func generateTokens(userId int) (string, string, error) {

	accessToken, err := utils.GenerateAccessToken(1)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := utils.GenerateRefreshToken(1)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil

}

func RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	refreshCookie, err := r.Cookie("refresh_token")
	if err != nil {
		http.Error(w, "Unauthorized : no refresh token found", http.StatusUnauthorized)
		return
	}

	claims, err := utils.ExtractToken(refreshCookie.Value)
	if err != nil {
		http.Error(w, "Unautorized : invalid resfresh token "+err.Error(), http.StatusUnauthorized)
		return
	}

	accessToken, refreshToken, err := generateTokens(claims.UserId)
	if err != nil {
		http.Error(w, "Internal server error : error creating the token"+err.Error(), http.StatusInternalServerError)
		return
	}

	var cookie http.Cookie
	createRefreshCookie(&refreshToken, &cookie)
	http.SetCookie(w, &cookie)

	err = storeRefreshToken(refreshToken, 1)
	if err != nil {
		http.Error(w, "Internal Server Error : "+err.Error(), http.StatusInternalServerError)
		return
	}

	authResponse := AuthenticationResponse{
		AccessToken: accessToken,
	}
	response, err := json.Marshal(authResponse)
	if err != nil {
		http.Error(w, "Error in creating the response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(response)
}

func storeRefreshToken(refreshToken string, userId int) error {
	err := utils.Rdb.Set(utils.Ctx, fmt.Sprintf("refresh_token:%d", userId), refreshToken, 86400*7).Err()
	if err != nil {
		return err
	}
	return nil
}

func RequestOTPHandler(w http.ResponseWriter, r *http.Request) {
	var OTPRequest OTPRequest
	if err := json.NewDecoder(r.Body).Decode(&OTPRequest); err != nil {
		http.Error(w, "Bad Request expecting 'email'", http.StatusBadRequest)
		return
	}
	fmt.Println(OTPRequest.Email)

	if OTPRequest.Email != "abdaladarwesh63@gmail.com" {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	n, _ := rand.Int(rand.Reader, big.NewInt(900000))
	otp := fmt.Sprintf("%06d", n.Int64()+100000)

	err := utils.Rdb.Set(utils.Ctx, fmt.Sprintf("otp:%s", OTPRequest.Email), otp, 3*time.Minute).Err()
	if err != nil {
		fmt.Printf("Inserting Error : %s \n", err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	fmt.Printf("OTP %s: %s\n", OTPRequest.Email, otp)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "OTP sent successfully check your terminal"}`))
}

func ValidateOTPHandler(w http.ResponseWriter, r *http.Request) {
	var request ValidateOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Bad Request expecting 'otp'", http.StatusBadRequest)
		return
	}

	attemptsKey := fmt.Sprintf("otp:attempts:%s", request.Email)
	attempts, err := utils.Rdb.Get(utils.Ctx, attemptsKey).Int()
	if attempts >= 3 && err == nil {
		http.Error(w, "Too many failed attempts. Please request a new OTP.", http.StatusTooManyRequests)
		return
	}

	otpKey := fmt.Sprintf("otp:%s", request.Email)
	res, err := utils.Rdb.Get(utils.Ctx, otpKey).Result()
	if err != nil {
		http.Error(w, "Invalid email", http.StatusUnauthorized)
		return
	}

	if res != request.OTP {
		pipe := utils.Rdb.Pipeline()
		pipe.Incr(utils.Ctx, attemptsKey)
		pipe.Expire(utils.Ctx, attemptsKey, 3*time.Minute)
		_, _ = pipe.Exec(utils.Ctx)

		http.Error(w, "Invalid OTP", http.StatusUnauthorized)
		return
	}

	utils.Rdb.Del(utils.Ctx, otpKey, attemptsKey)
	accessToken, refreshToken, err := generateTokens(1)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	var cookie http.Cookie
	createRefreshCookie(&refreshToken, &cookie)
	http.SetCookie(w, &cookie)

	authResponse := AuthenticationResponse{
		AccessToken: accessToken,
	}

	w.Header().Set("Content-Type", "application/json")
	response, err := json.Marshal(authResponse)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Write(response)
}
