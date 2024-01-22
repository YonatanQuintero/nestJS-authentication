import { ConflictException, Inject, Injectable, OnModuleInit, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { OAuth2Client } from 'google-auth-library';
import { User } from 'src/users/entities/user.entity';
import { AuthenticationService } from '../authentication.service';
import { Repository } from 'typeorm';
import { Permission } from 'src/iam/authorization/permission.type';

@Injectable()
export class GoogleAuthenticationService implements OnModuleInit {
    private aouthClient: OAuth2Client;

    constructor(
        private readonly configService: ConfigService,
        private readonly authenticationService: AuthenticationService,
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
    ) { }
    onModuleInit() {
        const clientId = this.configService.get('GOOGLE_CLIENT_ID');
        const clientIdSecret = this.configService.get('GOOGLE_CLIENT_ID_SECRET');
        this.aouthClient = new OAuth2Client(clientId, clientIdSecret);
    }

    async authenticate(token: string) {
        try {
            const loginTicket = await this.aouthClient.verifyIdToken({
                idToken: token,
            });

            const { email, sub: googleId, } = loginTicket.getPayload();
            const user = await this.userRepository.findOneBy({ googleId });
            if (user) {
                return this.authenticationService.generateTokens(user);
            } else {
                const newUser = await this.userRepository.save({ email, googleId, permissions: [Permission.CreateCoffee] });
                return this.authenticationService.generateTokens(newUser);
            }
        } catch (error) {
            // TODO: I'm not sure if mySQLduplicateKeyError handle error works
            const mySQLduplicateKeyError = 1602;
            if (error.code === mySQLduplicateKeyError) {
                throw new ConflictException('Email already in use');
            }
            throw new UnauthorizedException();
        }
    }

}
