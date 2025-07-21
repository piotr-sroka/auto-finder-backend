import { Injectable, UnauthorizedException } from '@nestjs/common';
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

    const user = (await this.prismaService.user.create({
      data: {
        email: dto.email,
        password: hashedPassword,
        name: dto.name ?? '',
      },
    })) as User;

    const token = this.jwtService.sign({ userId: user.id });
    return { token };
  }

  async login(dto: LoginAuthDto) {
    const user = (await this.prismaService.user.findUnique({
      where: { email: dto.email },
    })) as User;

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isValid = await bcrypt.compare(dto.password, user.password);

    if (!isValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const token = this.jwtService.sign({ userId: user.id });
    return { token };
  }
}
