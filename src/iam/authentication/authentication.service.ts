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

@Injectable()
export class AuthenticationService {

    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
        private readonly hashingService: HashingService,
        private readonly jwtService: JwtService,
        @Inject(jwtConfig.KEY)
        private readonly jwtConfiguration: ConfigType<typeof jwtConfig>,
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

        return await this.generateTokens(user);
    }

    async refreshTokens(refreshTokenDto: RefreshTokenDto) {
        try {

            const { sub } = await this.jwtService.verifyAsync<Pick<ActiveUserData, 'sub'>>(
                refreshTokenDto.refreshToken, {
                secret: this.jwtConfiguration.secret,
                audience: this.jwtConfiguration.audience,
                issuer: this.jwtConfiguration.issuer,
            });

            const user = await this.userRepository.findOneBy({
                id: sub,
            });

            if (!user) {
                throw new UnauthorizedException();
            }

            return this.generateTokens(user);

        } catch (error) {
            throw error
        }
    }

    private async generateTokens(user: User) {

        const [accessToken, refreshToken] = await Promise.all([
            this.signToken<Partial<ActiveUserData>>(
                user.id,
                this.jwtConfiguration.accessTokenTtl,
                { email: user.email },
            ),
            this.signToken(user.id, this.jwtConfiguration.refreshTokenTtl),
        ]);
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
