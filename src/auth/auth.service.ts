import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { CreateUserDto } from './dto/create-user.dto';
import { SignInDto } from './dto/sign-in.dto';
import { UsersRepository } from './users.repository';
import * as bcrypt from 'bcrypt';
import { JwtPayload } from './jwt-payload.interface';
import { JwtService } from '@nestjs/jwt';
import { VerifyResponseDto } from './dto/verify-response.dto';
import { ConfigService } from '@nestjs/config';
import { extractRolesFromAdminString } from 'src/utils';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(UsersRepository)
    private usersRepository: UsersRepository,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  signUp = (createUserDto: CreateUserDto): Promise<void> =>
    this.usersRepository.createUser(createUserDto);

  signIn = async (signInDto: SignInDto): Promise<{ accessToken: string }> => {
    const { email, password } = signInDto;
    const user = await this.usersRepository.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
      const payload: JwtPayload = { id: user.id };
      const accessToken = this.jwtService.sign(payload);
      return { accessToken };
    } else {
      throw new UnauthorizedException('Please check your login credentials');
    }
  };

  verify = async (jwtToken: string): Promise<VerifyResponseDto> => {
    try {
      const { id }: { id: string } = await this.jwtService.verify(jwtToken);
      const { email, username } = await this.usersRepository.findOne({
        id,
      });

      const role = extractRolesFromAdminString(
        this.configService.get('ADMIN_USERS'),
        email,
      );

      return { email, id, role, username };
    } catch (error) {
      throw new UnauthorizedException(error);
    }
  };
}
