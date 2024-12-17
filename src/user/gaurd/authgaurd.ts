import { HttpException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ExecutionContext, Injectable, CanActivate } from '@nestjs/common';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const token = request.headers['authorization'];

    if (!token) {
      throw new HttpException('Unauthorized', 401);
    }

    try {
      const decoded = this.jwtService.verify(token.replace('Bearer ', ''));
      request.user = decoded; 
      return true;
    } catch (error) {
      throw new HttpException('Unauthorized', 401);
    }
  }
}
