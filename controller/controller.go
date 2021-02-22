package controller

import (
	keys "auth/config"
	"auth/db"
	"auth/model"
	helper "auth/utils"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

func GenerateJWT(key []byte, typeOfToken string, email string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	exp := time.Now().Add(time.Minute * 20).Unix()
	if typeOfToken == "refresh" {
		exp = time.Now().Add(time.Hour * 24 * 60).Unix()
	}
	claims := &model.Claims{
		Email: email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: exp,
			IssuedAt:  time.Now().Unix(),
			Id:        helper.Random(),
		},
	}
	token.Claims = claims

	tokenString, err := token.SignedString(key)
	if err != nil {
		log.Println("Error in JWT token generation")
		return "", err
	}
	return tokenString, nil
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var user model.User
	var dbUser model.User

	json.NewDecoder(r.Body).Decode(&user)

	user.Password = helper.GetHash([]byte(user.Password))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection, err := db.GetDBCollection()
	if err != nil {
		json.NewEncoder(w).Encode(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	findErr := collection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&dbUser)
	if findErr != nil {
		_, err := collection.InsertOne(ctx, user)
		if err != nil {
			json.NewEncoder(w).Encode(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(user.Email)
		return
	}
	w.WriteHeader(http.StatusBadRequest)
}

func SignInHandler(w http.ResponseWriter, r *http.Request) {

	var user model.User
	var dbUser model.User

	w.Header().Set("Content-Type", "application/json")
	json.NewDecoder(r.Body).Decode(&user)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	//connection to DB
	collection, colErr := db.GetDBCollection()
	if colErr != nil {
		json.NewEncoder(w).Encode(colErr.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// find and validate user
	findErr := collection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&dbUser)
	if findErr != nil {
		json.NewEncoder(w).Encode(findErr.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	userPass := []byte(user.Password)
	dbPass := []byte(dbUser.Password)

	passErr := bcrypt.CompareHashAndPassword(dbPass, userPass)
	if passErr != nil {
		json.NewEncoder(w).Encode("Wrong Password!")
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// generate access and refresh tokens
	accTkn, err := GenerateJWT(keys.SECRET_KEY, "access", user.Email)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"jwtAcess Error":"` + err.Error() + `"}`))
		return
	}

	refTkn, err := GenerateJWT(([]byte(accTkn)), "refresh", user.Email)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"JwtRefresh Error":"` + err.Error() + `"}`))
		return
	}

	// set Cookie
	expiration := time.Now().Add(time.Hour * 24 * 60)
	cookie := http.Cookie{Name: "RefreshToken", Value: refTkn, Path: "/refresh", Expires: expiration, HttpOnly: true}
	http.SetCookie(w, &cookie)

	//start save refresh Token to database
	filter := bson.M{"email": user.Email}
	update := bson.M{
		"$set": bson.M{"token": helper.GetHash([]byte(refTkn))},
	}
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}

	result := collection.FindOneAndUpdate(ctx, filter, update, &opt)
	if result.Err() != nil {
		json.NewEncoder(w).Encode(result.Err())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// send access
	json.NewEncoder(w).Encode(accTkn)
}

func UpdateJWT(w http.ResponseWriter, r *http.Request) {
	acc_claims := &model.Claims{}

	extAcc, err := helper.ExtractToken(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	accTkn, err := jwt.ParseWithClaims(extAcc, acc_claims, func(token *jwt.Token) (interface{}, error) {
		return (keys.SECRET_KEY), nil
	})
	if err != nil || !accTkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	ref_claims := &model.Claims{}

	c, err := r.Cookie("RefreshToken")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	refTknStr := c.Value
	refTkn, err := jwt.ParseWithClaims(refTknStr, ref_claims, func(token *jwt.Token) (interface{}, error) {
		return ([]byte(extAcc)), nil
	})
	if err != nil || !refTkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	newAccTkn, err := GenerateJWT((keys.SECRET_KEY), "access", ref_claims.Email)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"JwtRefresh Error":"` + err.Error() + `"}`))
		return
	}

	newRefTkn, err := GenerateJWT(([]byte(newAccTkn)), "refresh", ref_claims.Email)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"JwtRefresh Error":"` + err.Error() + `"}`))
		return
	}

	//connect to DB and save new Refresh token
	collection, colErr := db.GetDBCollection()
	if colErr != nil {
		json.NewEncoder(w).Encode(colErr.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var thatUser model.User
	findErr := collection.FindOne(ctx, bson.M{"email": ref_claims.Email}).Decode(&thatUser)
	if findErr != nil {
		json.NewEncoder(w).Encode(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	error := bcrypt.CompareHashAndPassword([]byte(thatUser.Token), []byte(refTknStr))
	if error != nil {
		json.NewEncoder(w).Encode("Detected hacking!")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	filter := bson.M{"email": ref_claims.Email}
	update := bson.M{
		"$set": bson.M{"token": helper.GetHash([]byte(newRefTkn))},
	}
	upsert := true
	after := options.After
	opt := options.FindOneAndUpdateOptions{
		ReturnDocument: &after,
		Upsert:         &upsert,
	}
	result := collection.FindOneAndUpdate(ctx, filter, update, &opt)
	if result.Err() != nil {
		json.NewEncoder(w).Encode(result.Err())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//set Cookie
	expiration := time.Now().Add(time.Hour * 24 * 60)
	cookie := http.Cookie{Name: "RefreshToken", Value: newRefTkn, Path: "/refresh", Expires: expiration, HttpOnly: true}
	http.SetCookie(w, &cookie)

	json.NewEncoder(w).Encode(newAccTkn)
}
