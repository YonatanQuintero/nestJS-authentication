import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { request } from 'http';

@Injectable()
export class SessionGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    // isAuthenticated comes from passport
    return request.isAuthenticated();
  }
}
