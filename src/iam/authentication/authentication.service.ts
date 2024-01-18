import { ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { Repository } from 'typeorm';
import { HashingService } from '../hashing/hashing.service';
import { SignUpDto } from './dto/sign-up.dto/sign-up.dto';
import { SignInDto } from './dto/sign-in.dto/sign-in.dto';

@Injectable()
export class AuthenticationService {

    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
        private readonly hashingService: HashingService
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

        return true;

    }
}
