import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import {signInDto,signUpDto,forgotPasswordDto,changePasswordDto,refreshToken} from'./dto/index'
import { BadRequestException,ForbiddenException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import {JwtPayload,Tokens,JwtPayloadWithRt} from './types/index'
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class AuthService {
    constructor(private readonly prisma:PrismaService, private jwtService:JwtService, private mailService:MailerService){}

    public async signin(dto:signInDto){
        const {usernamme,password} = dto
        const user = await this.prisma.user.findUnique({
            where: {usernamme:usernamme},
          });
      
          if (!user) throw new ForbiddenException('Access Denied');
      
          const passwordMatches = await this.comparePasswords(user.password, password);
          if (!passwordMatches) throw new ForbiddenException('Access Denied wrong password');
          const tokens = await this.getTokens(user.id,user.email)
          await this.updateRtHash(user.id, tokens.refresh_token);4
          return tokens
    }

    public async signup(dto:signUpDto){
        const {usernamme,password,email} = dto

        const userExists = await this.prisma.user.findUnique({
            where: { usernamme:usernamme },
          });
      
          if (userExists) {
            throw new BadRequestException('user already exists');
          }

          const emailExists = await this.prisma.user.findUnique({
            where: { email:email },
          });
      
          if (emailExists) {
            throw new BadRequestException('emailaddress already exists');
          }
      
          const hashedPassword = await this.hashPassword(password);
          const defaultRole = 'user'

          await this.prisma.user.create({
            data:{
              email:email,usernamme:usernamme,password:hashedPassword,hashedRt:'',resettoken:'',role:defaultRole
            }
          })

          return { message: 'User created succefully' };
    }

    public async forgotPassword(dto:forgotPasswordDto){
        const {email} = dto
        const resetToken = this.sendToken(email)
        console.log(resetToken);
        await this.prisma.user.update({
          where:{
            email:email
          },
          data:{
            resettoken:resetToken
          }
        })

        return { message: 'otp sent succesfully' }
    }

    public async changePassword(dto:changePasswordDto){
        const {token,newPassword,email} = dto
        const user = await this.prisma.user.findUnique({
          where: {email:email},
        });
        console.log(user);

        if (!user) throw new ForbiddenException('Access Denied');

        if(user.resettoken === token){
          const hashToken = bcrypt.hashSync(newPassword,8)
          await this.prisma.user.update({
            where:{
              id:user.id
            },
            data:{
              password:hashToken,
              resettoken:null
            }
          })
          return { message: 'password reset succesfully' }
        }else{
          return {message:"access denied"}
        }
    }

    async logout(req:any): Promise<boolean> {
      const userId = req.user.sub
      console.log(userId);
      await this.prisma.user.updateMany({
        where: {
          id: userId,
          hashedRt: {
            not: null,
          },
        },
        data: {
          hashedRt: null,
        },
      });
      return true;
    }
  

    async hashPassword(password: string) {
        const saltOrRounds = 10;
        return await bcrypt.hashSync(password, saltOrRounds);
      }
    
      async comparePasswords(hash: string, password: string ) {
        return await bcrypt.compare(password, hash);
      }

      async updateRtHash(userId: number, rt: string): Promise<void> {
        const saltOrRounds = 10;
        const hash = await bcrypt.hash(rt, saltOrRounds);
        await this.prisma.user.update({
          where: {
            id: userId,
          },
          data: {
            hashedRt:hash
          },
        });
      }
      
      async refreshTokens(dto:refreshToken,req:any): Promise<Tokens> {
        const {userId,rt} = dto
        console.log({userId,rt} );
        const user = await this.prisma.user.findUnique({
          where: {
            id: userId,
          },
        });
        console.log(user);
        if (!user || !user.hashedRt) throw new ForbiddenException('Access Denied');
    
        const rtMatches = await bcrypt.compare(rt,user.hashedRt);
        console.log(rtMatches);
        if (!rtMatches) throw new ForbiddenException('Access Denied');
    
        const tokens = await this.getTokens(user.id, user.email);
        await this.updateRtHash(user.id, tokens.refresh_token);
    
        return tokens;
      }

      async getTokens(userId: number, email: string): Promise<Tokens> {
        const defaultRole = 'user'
        const jwtPayload: JwtPayload = {
          sub: userId,
          email: email,
          role: defaultRole
        };
    
        const [at, rt] = await Promise.all([
          this.jwtService.signAsync(jwtPayload, {
            secret: 'AT_SECRET',
            expiresIn: '15m',
          }),
          this.jwtService.signAsync(jwtPayload, {
            secret:'RT_SECRET',
            expiresIn: '7d',
          }),
        ]);
    
        return {
          access_token: at,
          refresh_token: rt,
        };
      }

      public generateOtp():string{
        
        const length = 6;
        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let OTP = '';
      
        for (let i = 0; i < length; i++) {
          const randomIndex = Math.floor(Math.random() * characters.length);
          OTP += characters.charAt(randomIndex);
        }
      
        return OTP;
      }

      public sendToken(email:string):string {
        let tokenData = this.generateOtp()
    
        this.mailService.sendMail({
          from: process.env.Email,
          to: email,
          subject: `forgot password`,
          text: `we sent an otp use it to reset your password: ${tokenData}`
        });

        return tokenData
      }
      
}
