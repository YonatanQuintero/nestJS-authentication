import { ConflictException, Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { Repository } from 'typeorm';
import { HashingService } from '../hashing/hashing.service';
import { SignUpDto } from './dto/sign-up.dto';
import { SignInDto } from './dto/sign-in.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigType } from '@nestjs/config';
import jwtConfig from '../config/jwt.config';
import { ActiveUserData } from '../interfaces/active-user-data.interface';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { InvalidateRefreshTokenError, RefreshTokenIdsStorage } from './refresh-token-ids.storage/refresh-token-ids.storage';
import { randomUUID } from 'crypto';
import { OtpAuthenticationService } from './otp-authentication.service';

@Injectable()
export class AuthenticationService {

    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
        private readonly hashingService: HashingService,
        private readonly jwtService: JwtService,
        @Inject(jwtConfig.KEY)
        private readonly jwtConfiguration: ConfigType<typeof jwtConfig>,
        private readonly refreshTokenIdsStorage: RefreshTokenIdsStorage,
        private readonly otpAuthService: OtpAuthenticationService,
    ) { }

    async signUp(signUpDto: SignUpDto) {

        const isSaved = await this.userRepository.existsBy({
            email: signUpDto.email
        });

        if (isSaved) {
            throw new ConflictException(
                `The user with the email ${signUpDto.email} already exists`
            );
        }

        const user = new User();
        user.email = signUpDto.email;
        user.password = await this.hashingService.hash(signUpDto.password);
        await this.userRepository.save(user);

    }

    async signIn(signInDto: SignInDto) {
        const user = await this.userRepository.findOneBy({
            email: signInDto.email
        });

        if (!user) {
            throw new UnauthorizedException('Invalid credentials');
        }

        const isEqual = await this.hashingService.compare(
            signInDto.password,
            user.password
        );

        if (!isEqual) {
            throw new UnauthorizedException('Invalid credentials');
        }

        if (user.isTfaEnabled) {
            const isValid = this.otpAuthService.verifyCode(
                signInDto.tfaCode,
                user.tfaSecret,
            );
            if (!isValid) {
                throw new UnauthorizedException('Invalid 2FA code');
            }
        }

        return await this.generateTokens(user);
    }

    async refreshTokens(refreshTokenDto: RefreshTokenDto) {
        try {

            const { sub, refreshTokenId } = await this.jwtService.verifyAsync
                <Pick<ActiveUserData, 'sub'> & { refreshTokenId: string }>(

                    refreshTokenDto.refreshToken, {
                    secret: this.jwtConfiguration.secret,
                    audience: this.jwtConfiguration.audience,
                    issuer: this.jwtConfiguration.issuer,

                });

            const user = await this.userRepository.findOneBy({
                id: sub,
            });

            if (!user) {
                throw new Error('Invalid credentials');
            }

            const isValid = await this.refreshTokenIdsStorage.validate(
                user.id,
                refreshTokenId
            );

            if (isValid) {
                await this.refreshTokenIdsStorage.invalidate(user.id);
            } else {
                throw new Error('Refresh token is not valid');
            }

            return this.generateTokens(user);

        } catch (error) {

            if (error instanceof InvalidateRefreshTokenError) {
                // Take action: notify the user that their refresh token  might have been stolen?
                throw new UnauthorizedException('Access denied');
            }

            throw new UnauthorizedException();
        }
    }

    async generateTokens(user: User) {
        const refreshTokenId = randomUUID();
        const [accessToken, refreshToken] = await Promise.all([
            this.signToken<Partial<ActiveUserData>>(
                user.id,
                this.jwtConfiguration.accessTokenTtl,
                {
                    email: user.email,
                    role: user.role,
                    permissions: user.permissions,
                },
            ),
            this.signToken(user.id, this.jwtConfiguration.refreshTokenTtl, {
                refreshTokenId,
            }),
        ]);
        await this.refreshTokenIdsStorage.insert(user.id, refreshTokenId);
        return {
            accessToken,
            refreshToken,
        };
    }

    private async signToken<T>(userId: number, expiresIn: number, payload?: T) {
        return await this.jwtService.signAsync({
            sub: userId,
            ...payload
        }, {
            audience: this.jwtConfiguration.audience,
            issuer: this.jwtConfiguration.issuer,
            secret: this.jwtConfiguration.secret,
            expiresIn: expiresIn
        });
    }

}
