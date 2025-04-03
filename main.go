package main

import (
	"context"
	"log"
	"net"

	authservice "github.com/centodiechi/Auth/AuthService"
	apex "github.com/centodiechi/Auth/protos/v1"
	"github.com/go-chi/cors"

	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const (
	grpcPort    = ":50051"
	httpPort    = ":8080"
	redisAddr   = "localhost:6379"
	postgresDSN = "host=localhost user=admin password=admin dbname=user_db port=5432 sslmode=disable"
)

var (
	DB          *gorm.DB
	RedisClient *redis.Client
)

func init() {
	initPostgres()
	initRedis()
}

func initPostgres() {
	var err error
	DB, err = gorm.Open(postgres.Open(postgresDSN), &gorm.Config{})
	if err != nil {
		log.Fatalf("❌ Failed to connect to PostgreSQL: %v", err)
	}

	if err := DB.AutoMigrate(&authservice.User{}); err != nil {
		log.Fatalf("❌ Failed to migrate database: %v", err)
	}

	log.Println("✅ PostgreSQL connected and migrated successfully")
}

func initRedis() {
	RedisClient = redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})

	_, err := RedisClient.Ping(context.Background()).Result()
	if err != nil {
		log.Fatalf("❌ Failed to connect to Redis: %v", err)
	}

	log.Println("✅ Redis connected successfully")
}

func main() {
	authSvc := &authservice.AuthSvc{
		DB:          DB,
		RedisClient: RedisClient,
	}

	go startGRPCServer(authSvc)

	startHTTPServer(authSvc)
}

func startGRPCServer(authSvc *authservice.AuthSvc) {
	listener, err := net.Listen("tcp", grpcPort)
	if err != nil {
		log.Fatalf("❌ Failed to listen on %s: %v", grpcPort, err)
	}

	grpcServer := grpc.NewServer()
	apex.RegisterAuthServiceServer(grpcServer, authSvc)

	log.Printf("🚀 gRPC server listening on %s", grpcPort)
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("❌ Failed to start gRPC server: %v", err)
	}
}

func startHTTPServer(authSvc *authservice.AuthSvc) {
	router := chi.NewRouter()
	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: true,
	}))
	httpServer := authservice.NewHTTPServer(authSvc)
	router.Mount("/", httpServer.Routes())

	log.Printf("🌍 HTTP server listening on %s", httpPort)
	if err := http.ListenAndServe(httpPort, router); err != nil {
		log.Fatalf("❌ Failed to start HTTP server: %v", err)
	}
}
