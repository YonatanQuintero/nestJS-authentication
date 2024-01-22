import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AccessTokenGuard } from '../access-token/access-token.guard';
import { AuthType } from '../../enums/auth-type.enum';
import { AUTH_TYPE_KEY } from '../../decorators/auth.decorator';
import { ApiKeyGuard } from '../api-key/api-key.guard';

@Injectable()
export class AuthenticationGuard implements CanActivate {

  private static readonly defaultAuthType: AuthType = AuthType.Bearer;
  private readonly authTypeGuardMap: Map<AuthType, CanActivate | CanActivate[]>;

  constructor(
    private readonly reflector: Reflector,
    private readonly accessTokenGuard: AccessTokenGuard,
    private readonly apiKeyGuard: ApiKeyGuard
  ) {
    this.authTypeGuardMap = new Map<AuthType, CanActivate | CanActivate[]>();
    this.authTypeGuardMap.set(AuthType.Bearer, this.accessTokenGuard);
    this.authTypeGuardMap.set(AuthType.ApiKey, this.apiKeyGuard);
    this.authTypeGuardMap.set(AuthType.None, { canActivate: () => true });
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {

    const authTypes = this.reflector.getAllAndOverride<AuthType[]>(
      AUTH_TYPE_KEY,
      [context.getHandler(), context.getClass()],
    ) ?? [AuthenticationGuard.defaultAuthType];

    const guards = authTypes.map((type) => this.authTypeGuardMap.get(type)).flat();

    let error = new UnauthorizedException();

    for (const instance of guards) {

      const canActivate = await Promise.resolve(
        instance.canActivate(context),
      ).catch((err) => { error = err; });

      if (canActivate) {
        return true;
      }
    }

    throw error;

  }
}
