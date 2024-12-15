package main

import (
	"context"

	"github.com/go-redis/redis/v8"
)

type RedisStore struct {
	client *redis.Client
}

func NewRedisStore(addr, password string, db int) *RedisStore {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})
	return &RedisStore{
		client: rdb,
	}
}

func (rs *RedisStore) CreateRoom(ctx context.Context, roomID, algorithm string) error {
	return rs.client.HSet(ctx, "room:"+roomID, "algorithm", algorithm).Err()
}

func (rs *RedisStore) DeleteRoom(ctx context.Context, roomID string) error {
	return rs.client.Del(ctx, "room:"+roomID, "room:"+roomID+":clients", "room:"+roomID+":public_keys").Err()
}

func (rs *RedisStore) AddClientToRoom(ctx context.Context, roomID, clientID string) error {
	return rs.client.HSet(ctx, "room:"+roomID+":clients", clientID, "").Err()
}

func (rs *RedisStore) RemoveClientFromRoom(ctx context.Context, roomID, clientID string) error {
	return rs.client.HDel(ctx, "room:"+roomID+":clients", clientID).Err()
}

func (rs *RedisStore) SavePublicKey(ctx context.Context, roomID, clientID, publicKey string) error {
	return rs.client.HSet(ctx, "room:"+roomID+":public_keys", clientID, publicKey).Err()
}

func (rs *RedisStore) GetPublicKeys(ctx context.Context, roomID string) (map[string]string, error) {
	return rs.client.HGetAll(ctx, "room:"+roomID+":public_keys").Result()
}

func (rs *RedisStore) RoomExists(ctx context.Context, roomID string) (bool, error) {
	exists, err := rs.client.Exists(ctx, "room:"+roomID).Result()
	return exists > 0, err
}

func (rs *RedisStore) GetAlgorithm(ctx context.Context, roomID string) (string, error) {
	return rs.client.HGet(ctx, "room:"+roomID, "algorithm").Result()
}
