package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	"github.com/go-zoo/bone"
	"github.com/jmoiron/sqlx"
	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/clients"
	"github.com/mainflux/mainflux/clients/api"
	grpcapi "github.com/mainflux/mainflux/clients/api/grpc"
	clientapi "github.com/mainflux/mainflux/clients/api/http/clients"
	groupapi "github.com/mainflux/mainflux/clients/api/http/groups"
	policyapi "github.com/mainflux/mainflux/clients/api/http/policies"
	"github.com/mainflux/mainflux/clients/jwt"
	"github.com/mainflux/mainflux/clients/postgres"
	"github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/mainflux/mainflux/pkg/ulid"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

const (
	stopWaitTime = 5 * time.Second

	defLogLevel      = "debug"
	defSecretKey     = "clientsecret"
	defAdminIdentity = "admin@example.com"
	defAdminSecret   = "12345678"
	defDBHost        = "localhost"
	defDBPort        = "5432"
	defDBUser        = "uv"
	defDBPass        = "uv"
	defDB            = "clients"
	defDBSSLMode     = "disable"
	defDBSSLCert     = ""
	defDBSSLKey      = ""
	defDBSSLRootCert = ""
	defHTTPPort      = "9191"
	defGRPCPort      = "9192"
	defServerCert    = ""
	defServerKey     = ""
	defJaegerURL     = "http://localhost:6831"

	envLogLevel      = "UV_CLIENTS_LOG_LEVEL"
	envSecretKey     = "UV_CLIENTS_SECRET_KEY"
	envAdminIdentity = "UV_CLIENTS_ADMIN_EMAIL"
	envAdminSecret   = "UV_CLIENTS_ADMIN_PASSWORD"
	envDBHost        = "UV_CLIENTS_DB_HOST"
	envDBPort        = "UV_CLIENTS_DB_PORT"
	envDBUser        = "UV_CLIENTS_DB_USER"
	envDBPass        = "UV_CLIENTS_DB_PASS"
	envDB            = "UV_CLIENTS_DB"
	envDBSSLMode     = "UV_CLIENTS_DB_SSL_MODE"
	envDBSSLCert     = "UV_CLIENTS_DB_SSL_CERT"
	envDBSSLKey      = "UV_CLIENTS_DB_SSL_KEY"
	envDBSSLRootCert = "UV_CLIENTS_DB_SSL_ROOT_CERT"
	envHTTPPort      = "UV_CLIENTS_HTTP_PORT"
	envGRPCPort      = "UV_CLIENTS_GRPC_PORT"
	envServerCert    = "UV_CLIENTS_SERVER_CERT"
	envServerKey     = "UV_CLIENTS_SERVER_KEY"
	envJaegerURL     = "UV_JAEGER_URL"
)

type config struct {
	logLevel      string
	secretKey     string
	adminIdentity string
	adminSecret   string
	dbConfig      postgres.Config
	httpPort      string
	grpcPort      string
	serverCert    string
	serverKey     string
	jaegerURL     string
}

func main() {
	cfg := loadConfig()
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	logger, err := logger.New(os.Stdout, cfg.logLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}
	db := connectToDB(cfg.dbConfig, logger)
	defer db.Close()

	tp, err := initJaeger("clients", cfg.jaegerURL)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to init Jaeger: %s", err))
	}
	defer func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			logger.Error(fmt.Sprintf("Error shutting down tracer provider: %v", err))
		}
	}()
	tracer := otel.Tracer("clients")

	svc := newService(db, tracer, cfg, logger)

	g.Go(func() error {
		return startHTTPServer(ctx, svc, cfg.httpPort, cfg.serverCert, cfg.serverKey, logger)
	})
	g.Go(func() error {
		return startGRPCServer(ctx, svc, cfg.grpcPort, cfg.serverCert, cfg.serverKey, logger)
	})

	g.Go(func() error {
		if sig := errors.SignalHandler(ctx); sig != nil {
			cancel()
			logger.Info(fmt.Sprintf("Clients service shutdown by signal: %s", sig))
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		logger.Error(fmt.Sprintf("Clients service terminated: %s", err))
	}
}

func loadConfig() config {
	dbConfig := postgres.Config{
		Host:        mainflux.Env(envDBHost, defDBHost),
		Port:        mainflux.Env(envDBPort, defDBPort),
		User:        mainflux.Env(envDBUser, defDBUser),
		Pass:        mainflux.Env(envDBPass, defDBPass),
		Name:        mainflux.Env(envDB, defDB),
		SSLMode:     mainflux.Env(envDBSSLMode, defDBSSLMode),
		SSLCert:     mainflux.Env(envDBSSLCert, defDBSSLCert),
		SSLKey:      mainflux.Env(envDBSSLKey, defDBSSLKey),
		SSLRootCert: mainflux.Env(envDBSSLRootCert, defDBSSLRootCert),
	}

	return config{
		logLevel:      mainflux.Env(envLogLevel, defLogLevel),
		secretKey:     mainflux.Env(envSecretKey, defSecretKey),
		adminIdentity: mainflux.Env(envAdminIdentity, defAdminIdentity),
		adminSecret:   mainflux.Env(envAdminSecret, defAdminSecret),
		dbConfig:      dbConfig,
		httpPort:      mainflux.Env(envHTTPPort, defHTTPPort),
		grpcPort:      mainflux.Env(envGRPCPort, defGRPCPort),
		serverCert:    mainflux.Env(envServerCert, defServerCert),
		serverKey:     mainflux.Env(envServerKey, defServerKey),
		jaegerURL:     mainflux.Env(envJaegerURL, defJaegerURL),
	}

}

func initJaeger(svcName, url string) (*tracesdk.TracerProvider, error) {
	exporter, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(url)))
	if err != nil {
		return nil, err
	}
	tp := tracesdk.NewTracerProvider(
		tracesdk.WithSampler(tracesdk.AlwaysSample()),
		tracesdk.WithBatcher(exporter),
		tracesdk.WithSpanProcessor(tracesdk.NewBatchSpanProcessor(exporter)),
		tracesdk.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(svcName),
		)),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))

	return tp, nil
}

func connectToDB(dbConfig postgres.Config, logger logger.Logger) *sqlx.DB {
	db, err := postgres.Connect(dbConfig)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to connect to postgres: %s", err))
		os.Exit(1)
	}
	return db
}

func newService(db *sqlx.DB, tracer trace.Tracer, c config, logger logger.Logger) clients.Service {
	database := postgres.NewDatabase(db, tracer)
	cRepo := postgres.NewClientRepo(database)
	gRepo := postgres.NewGroupRepo(database)
	pRepo := postgres.NewPolicyRepo(database)

	idp := ulid.New()
	tokenizer := jwt.NewTokenRepo([]byte(c.secretKey))
	tokenizer = jwt.NewTokenRepoMiddleware(tokenizer, tracer)
	svc := clients.NewService(cRepo, gRepo, pRepo, tokenizer, idp)

	svc = api.TracingMiddleware(svc, tracer)
	svc = api.LoggingMiddleware(svc, logger)
	svc = api.MetricsMiddleware(
		svc,
		kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: "clients",
			Subsystem: "api",
			Name:      "request_count",
			Help:      "Number of requests received.",
		}, []string{"method"}),
		kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
			Namespace: "clients",
			Subsystem: "api",
			Name:      "request_latency_microseconds",
			Help:      "Total duration of requests in microseconds.",
		}, []string{"method"}),
	)
	if err := createAdmin(cRepo, c, svc); err != nil {
		logger.Error(fmt.Sprintf("Failed to create admin client: %s", err))
		os.Exit(1)
	}
	return svc
}

func startHTTPServer(ctx context.Context, svc clients.Service, port string, certFile string, keyFile string, logger logger.Logger) error {
	p := fmt.Sprintf(":%s", port)
	errCh := make(chan error)
	m := bone.New()
	clientapi.MakeClientsHandler(svc, m, logger)
	groupapi.MakeGroupsHandler(svc, m, logger)
	policyapi.MakePolicyHandler(svc, m, logger)
	server := &http.Server{Addr: p, Handler: m}

	switch {
	case certFile != "" || keyFile != "":
		logger.Info(fmt.Sprintf("Clients service started using https, cert %s key %s, exposed port %s", certFile, keyFile, port))
		go func() {
			errCh <- server.ListenAndServeTLS(certFile, keyFile)
		}()
	default:
		logger.Info(fmt.Sprintf("Clients service started using http, exposed port %s", port))
		go func() {
			errCh <- server.ListenAndServe()
		}()
	}

	select {
	case <-ctx.Done():
		ctxShutdown, cancelShutdown := context.WithTimeout(context.Background(), stopWaitTime)
		defer cancelShutdown()
		if err := server.Shutdown(ctxShutdown); err != nil {
			logger.Error(fmt.Sprintf("Clients service error occurred during shutdown at %s: %s", p, err))
			return fmt.Errorf("clients service occurred during shutdown at %s: %w", p, err)
		}
		logger.Info(fmt.Sprintf("Clients service shutdown of http at %s", p))
		return nil
	case err := <-errCh:
		return err
	}

}

func startGRPCServer(ctx context.Context, svc clients.Service, port string, certFile string, keyFile string, logger logger.Logger) error {
	p := fmt.Sprintf(":%s", port)
	errCh := make(chan error)

	listener, err := net.Listen("tcp", p)
	if err != nil {
		return fmt.Errorf("failed to listen on port %s: %w", port, err)
	}

	var server *grpc.Server
	switch {
	case certFile != "" || keyFile != "":
		creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("failed to load auth certificates: %w", err)
		}
		logger.Info(fmt.Sprintf("Clients gRPC service started using https on port %s with cert %s key %s", port, certFile, keyFile))
		server = grpc.NewServer(grpc.Creds(creds))
	default:
		logger.Info(fmt.Sprintf("Clients gRPC service started using http on port %s", port))
		server = grpc.NewServer()
	}

	reflection.Register(server)
	clients.RegisterAuthServiceServer(server, grpcapi.NewServer(svc))
	logger.Info(fmt.Sprintf("Clients gRPC service started, exposed port %s", port))
	go func() {
		errCh <- server.Serve(listener)
	}()

	select {
	case <-ctx.Done():
		c := make(chan bool)
		go func() {
			defer close(c)
			server.GracefulStop()
		}()
		select {
		case <-c:
		case <-time.After(stopWaitTime):
		}
		logger.Info(fmt.Sprintf("Authentication gRPC service shutdown at %s", p))
		return nil
	case err := <-errCh:
		return err
	}
}

func createAdmin(crepo clients.ClientRepository, c config, svc clients.Service) error {
	id, err := ulid.New().ID()
	if err != nil {
		return err
	}
	client := clients.Client{
		ID:   id,
		Name: "admin",
		Credentials: clients.Credentials{
			Identity: c.adminIdentity,
			Secret:   c.adminSecret,
		},
		Metadata: clients.Metadata{
			"role": "admin",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Status:    clients.EnabledStatusKey,
	}

	if _, err := crepo.RetrieveByIdentity(context.Background(), client.Credentials.Identity); err == nil {
		return nil
	}

	// Create an admin
	if _, err = crepo.Save(context.Background(), client); err != nil {
		return err
	}
	_, err = svc.IssueToken(context.Background(), client)
	if err != nil {
		return err
	}

	return nil
}
