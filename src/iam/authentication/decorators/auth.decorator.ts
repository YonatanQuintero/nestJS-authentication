import { SetMetadata } from "@nestjs/common";
import { AuthType } from "../enums/auth-type.enum";

export const AUTH_TYPE_KEY = 'AUTH_TYPE_KEY';

export const Auth = (...authTypes: AuthType[]) => {
    return SetMetadata(AUTH_TYPE_KEY, authTypes);
}