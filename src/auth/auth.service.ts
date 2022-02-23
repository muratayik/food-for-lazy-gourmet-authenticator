import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { CreateUserDto } from './dto/create-user.dto';
import { SignInDto } from './dto/sign-in.dto';
import { UsersRepository } from './users.repository';
import * as bcrypt from 'bcrypt';
import { JwtPayload } from './jwt-payload.interface';
import { JwtService } from '@nestjs/jwt';
import { VerifyResponseDto } from './dto/verify-response.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(UsersRepository)
    private usersRepository: UsersRepository,
    private jwtService: JwtService,
  ) {}

  signUp = (createUserDto: CreateUserDto): Promise<void> =>
    this.usersRepository.createUser(createUserDto);

  signIn = async (signInDto: SignInDto): Promise<{ accessToken: string }> => {
    const { email, password } = signInDto;
    const user = await this.usersRepository.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
      const payload: JwtPayload = { email };
      const accessToken = this.jwtService.sign(payload);
      return { accessToken };
    } else {
      throw new UnauthorizedException('Please check your login credentials');
    }
  };

  verify = async (jwtToken: string): Promise<VerifyResponseDto> => {
    try {
      const { email }: { email: string } = await this.jwtService.verify(
        jwtToken,
      );
      const { username } = await this.usersRepository.findOne({ email });
      return { isSuccess: true, email, username: username };
    } catch (error) {
      if (
        error.message === 'invalid signature' ||
        error.message === 'jwt expired'
      ) {
        return { isSuccess: false, email: '', username: '' };
      }
      throw new UnauthorizedException(error);
    }
  };
}
