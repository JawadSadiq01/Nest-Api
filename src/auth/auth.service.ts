import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import * as argon from "argon2";
import { AuthDto } from "./dto";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";
import { async } from "rxjs";

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) { }

  async signin(dto: AuthDto) {
    //  Find user
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      }
    })

    // throw error if user not exist 
    if (!user) throw new ForbiddenException('Email not found.')

    // check password
    const pwMatches = await argon.verify(
      user.hash,
      dto.password
    )

    // throw error if user enters wrong password 
    if (!pwMatches) throw new ForbiddenException('Wrong password')

    return this.signToken(user.id, user.email);
  }

  async signup(dto: AuthDto) {
    try {
      const hash = await argon.hash(dto.password)

      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        }
      });


      return this.signToken(user.id, user.email);
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') throw new ForbiddenException('Email already registered.');
      }
      throw error
    }
  }

  async signToken(
    userId: number,
    email: string
  ): Promise<{access_token: string}> {

    const secret = this.config.get('JWT_SECRET');
    const payload = {
      sub: userId,
      email,
    }

    const token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret: secret,
    });

    return { access_token: token };
  }
}