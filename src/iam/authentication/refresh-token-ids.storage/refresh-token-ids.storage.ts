import { Inject, Injectable, OnApplicationBootstrap, OnApplicationShutdown } from "@nestjs/common";
import { ConfigType } from "@nestjs/config";
import Redis from "ioredis";
import redisConfig from "src/iam/config/redis.config";

export class InvalidateRefreshTokenError extends Error { }

@Injectable()
export class RefreshTokenIdsStorage implements OnApplicationBootstrap, OnApplicationShutdown {

    private redisClient: Redis;

    constructor(
        @Inject(redisConfig.KEY)
        private readonly redisConfiguration: ConfigType<typeof redisConfig>,
    ) {
    }

    onApplicationBootstrap() {
        // TODO: Ideally, we should move this to the dedicated "RedisModule".
        this.redisClient = new Redis({
            host: this.redisConfiguration.host,
            port: this.redisConfiguration.port
        });
    }

    onApplicationShutdown(signal?: string) {
        return this.redisClient.quit();
    }

    async insert(userId: number, tokenId: string): Promise<void> {
        await this.redisClient.set(this.getKey(userId), tokenId);
    }

    async validate(userId: number, tokenId: string): Promise<Boolean> {
        const storeId = await this.redisClient.get(this.getKey(userId));

        if (storeId !== tokenId) {
            throw new InvalidateRefreshTokenError();
        }

        return true;
    }

    async invalidate(userId: number): Promise<void> {
        await this.redisClient.del(this.getKey(userId));
    }

    private getKey(userId: number): string {
        return `user-:${userId}`;
    }

}
