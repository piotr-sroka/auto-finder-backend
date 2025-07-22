import {
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { RegisterAuthDto } from './dto/register-auth.dto';
import * as bcrypt from 'bcrypt';
import { User } from 'generated/prisma';
import { LoginAuthDto } from './dto/login-auth.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async register(dto: RegisterAuthDto) {
    const hashedPassword: string = await bcrypt.hash(dto.password, 10);

    try {
      const user = (await this.prismaService.user.create({
        data: {
          email: dto.email,
          password: hashedPassword,
          name: dto.name ?? '',
          surname: dto.surname ?? '',
        },
      })) as User;

      const token = this.jwtService.sign({ userId: user.id });
      return { token };
    } catch (error) {
      if (error.code === 'P2002') {
        throw new HttpException(
          {
            statusCode: HttpStatus.CONFLICT,
            message: 'Validation error',
            errors: { email: 'email is already registered' },
          },
          HttpStatus.CONFLICT,
        );
      }
    }
  }

  async login(dto: LoginAuthDto) {
    try {
      const user = (await this.prismaService.user.findUnique({
        where: { email: dto.email },
      })) as User;

      if (!user) {
        throw new UnauthorizedException('Invalid credentials');
      }

      const isValid = await bcrypt.compare(dto.password, user.password);

      if (!isValid) {
        throw new HttpException(
          {
            statusCode: HttpStatus.UNAUTHORIZED,
            message: 'Invalid credentials',
            errors: { password: 'Invalid password' },
          },
          HttpStatus.UNAUTHORIZED,
        );
      }

      const token = this.jwtService.sign({ userId: user.id });
      return { token };
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw new HttpException(
          {
            statusCode: HttpStatus.UNAUTHORIZED,
            message: 'Invalid credentials',
            errors: {
              email: 'Email and password do not match',
              password: 'Email and password do not match',
            },
          },
          HttpStatus.UNAUTHORIZED,
        );
      }
      throw new HttpException(
        {
          statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'Internal server error',
          errors: { general: 'An unexpected error occurred' },
        },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}
