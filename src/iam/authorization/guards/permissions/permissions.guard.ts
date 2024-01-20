import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../../decorators/roles.decorator';
import { Role } from 'src/users/enums/role.enum';
import { ActiveUserData } from 'src/iam/interfaces/active-user-data.interface';
import { REQUEST_USER_KEY } from 'src/iam/iam.constants';
import { PermissionType } from '../../permission.type';
import { PERMISSIONS_KEY } from '../../decorators/permissions.decorator';

@Injectable()
export class PermissionsGuard implements CanActivate {

  constructor(
    private readonly reflector: Reflector
  ) { }

  canActivate(context: ExecutionContext): boolean {

    const contextPermissions = this.reflector.getAllAndOverride<PermissionType[]>(
      PERMISSIONS_KEY,
      [
        context.getHandler(),
        context.getClass(),
      ]);

    if (!contextPermissions) {
      return true;
    }

    const user: ActiveUserData = context.switchToHttp().getRequest()[
      REQUEST_USER_KEY
    ];

    return contextPermissions.every((permission) => {
      return user.permissions.includes(permission);
    });
  }

}
