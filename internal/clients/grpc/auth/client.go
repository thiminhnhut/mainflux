// Copyright (c) Magistrala
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	mainflux "github.com/absmach/magistrala"
	authgrpc "github.com/absmach/magistrala/auth/api/grpc"
	grpcclient "github.com/absmach/magistrala/internal/clients/grpc"
	"github.com/absmach/magistrala/internal/env"
	"github.com/absmach/magistrala/pkg/errors"
	thingsauth "github.com/absmach/magistrala/things/api/grpc"
)

const (
	envAuthGrpcPrefix  = "MG_AUTH_GRPC_"
	envAuthzGrpcPrefix = "MG_THINGS_AUTH_GRPC_"
)

var errGrpcConfig = errors.New("failed to load grpc configuration")

// Setup loads Auth gRPC configuration from environment variable and creates new Auth gRPC API.
func Setup(svcName string) (mainflux.AuthServiceClient, grpcclient.ClientHandler, error) {
	config := grpcclient.Config{}
	if err := env.Parse(&config, env.Options{Prefix: envAuthGrpcPrefix}); err != nil {
		return nil, nil, errors.Wrap(errGrpcConfig, err)
	}
	c, ch, err := grpcclient.Setup(config, svcName)
	if err != nil {
		return nil, nil, err
	}

	return authgrpc.NewClient(c.ClientConn, config.Timeout), ch, nil
}

// Setup loads Auth gRPC configuration from environment variable and creates new Auth gRPC API.
func SetupAuthz(svcName string) (mainflux.AuthzServiceClient, grpcclient.ClientHandler, error) {
	config := grpcclient.Config{}
	if err := env.Parse(&config, env.Options{Prefix: envAuthzGrpcPrefix}); err != nil {
		return nil, nil, errors.Wrap(errGrpcConfig, err)
	}
	c, ch, err := grpcclient.Setup(config, svcName)
	if err != nil {
		return nil, nil, err
	}

	return thingsauth.NewClient(c.ClientConn, config.Timeout), ch, nil
}
