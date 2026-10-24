package utils

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

var Rdb *redis.Client
var Ctx = context.Background()

func InitRedis(){

	Rdb = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		Password: "",
		DB: 0,
	})

	_, err := Rdb.Ping(Ctx).Result()
	if err != nil{
		fmt.Printf("Error happened While initializing redis %s \n", err.Error())
		panic(err)
	}

	fmt.Println("Redis is initialized succesfully")
}
