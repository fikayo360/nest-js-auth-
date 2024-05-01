import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Request } from 'express';
import { ForbiddenException, Injectable } from '@nestjs/common';

import { JwtPayloadWithRt,JwtPayload } from '../types';

@Injectable()
export class RtStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  // constructor() {
  //   super({
  //     jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  //     secretOrKey: 'RT_SECRET',
  //     passReqToCallback: true,
  //   });
  // }

  // validate(req: Request, payload: JwtPayload): JwtPayloadWithRt {

  //   const refreshToken = req
  //     ?.get('authorization')
  //     ?.replace('Bearer', '')
  //     .trim();

  //   if (!refreshToken) throw new ForbiddenException('Refresh token malformed');
  //   console.log(payload);
  //   return {
  //     ...payload,
  //     refreshToken,
  //   };
  // }
  
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        RtStrategy.extractJWT,
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      secretOrKey:'RT_SECRET',
    });
  }

  private static extractJWT(req: Request): string | null {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer")) {
      console.log('no token! access denied')
      return "no token! access denied"
    }
  
    const tokenData = authHeader.split(" ");
    const token = tokenData[1]; 
    return token
  }

  async validate(req: Request, payload: JwtPayloadWithRt) {
    const refreshToken = req
        ?.get('authorization')
        ?.replace('Bearer', '')
        .trim();
  
      if (!refreshToken) throw new ForbiddenException('Refresh token malformed');
    return payload;
  }

}