package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/bluemediaapp/models"
	"github.com/bwmarrin/snowflake"
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	app    = fiber.New()
	client *mongo.Client
	config *Config

	mctx                = context.Background()
	usersCollection     *mongo.Collection
	userLoginCollection *mongo.Collection
)

func main() {
	config = &Config{
		port:     os.Getenv("port"),
		mongoUri: os.Getenv("mongo_uri"),
	}
	snowflake.Epoch = time.Date(2020, time.January, 0, 0, 0, 0, 0, time.UTC).Unix()
	log.Print(snowflake.Epoch)
	snowNode, _ := snowflake.NewNode(0)

	app.Get("/login", func(ctx *fiber.Ctx) error {
		userName := ctx.Get("username", "")
		password := ctx.Get("password", "")

		if userName == "" || password == "" {
			return ctx.Status(400).SendString("username or password not provided.")
		}

		login, err := getUserLogin(userName)
		if err != nil {
			return ctx.Status(403).SendString("Invalid username")
		}

		isCorrect, err := argon2id.ComparePasswordAndHash(password, login.Password)
		if err != nil {
			return err
		}

		if !isCorrect {
			return ctx.Status(403).SendString("Invalid password")
		}
		token, err := CreateJWTToken(login.Id)
		if err != nil {
			return err
		}
		return ctx.SendString(token)
	})
	app.Get("/register", func(ctx *fiber.Ctx) error {
		userName := ctx.Get("username", "")
		password := ctx.Get("password", "")
		userId := snowNode.Generate().Int64()

		if userName == "" || password == "" {
			return ctx.Status(400).SendString("username or password not provided.")
		}

		_, err := getUserLogin(userName)
		if err == nil {
			// User already exists
			return ctx.Status(400).SendString("Username is already taken")
		}

		hashedPassword, err := argon2id.CreateHash(password, argon2id.DefaultParams)

		userLogin := models.UserLogin{
			Id:       userId,
			Username: userName,
			Password: hashedPassword,
		}
		user := models.DatabaseUser{
			Id:        userId,
			Username:  userName,
			Interests: make(map[string]int64),
		}
		_, err = userLoginCollection.InsertOne(mctx, userLogin)
		if err != nil {
			return err
		}
		_, err = usersCollection.InsertOne(mctx, user)
		if err != nil {
			return err
		}

		token, err := CreateJWTToken(userId)
		if err != nil {
			return err
		}
		return ctx.SendString(token)
	})

	initDb()
	log.Fatal(app.Listen(config.port))
}

func initDb() {
	// Connect mongo
	var err error
	client, err = mongo.NewClient(options.Client().ApplyURI(config.mongoUri))
	if err != nil {
		log.Fatal(err)
	}

	err = client.Connect(mctx)
	if err != nil {
		log.Fatal(err)
	}

	// Setup tables
	db := client.Database("blue")
	usersCollection = db.Collection("users")
	userLoginCollection = db.Collection("users_login")
}

// Db utils
func getUserLogin(userName string) (models.UserLogin, error) {
	query := bson.D{{"username", userName}}
	rawVideo := userLoginCollection.FindOne(mctx, query)
	var userLogin models.UserLogin
	err := rawVideo.Decode(&userLogin)
	if err != nil {
		return models.UserLogin{}, err
	}
	return userLogin, nil
}
