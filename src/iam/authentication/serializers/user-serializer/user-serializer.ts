import { PassportSerializer } from "@nestjs/passport";
import { ActiveUserData } from "src/iam/interfaces/active-user-data.interface";
import { User } from "src/users/entities/user.entity";

type TDone = (err: Error, user: ActiveUserData) => void;

export class UserSerializer extends PassportSerializer {
    serializeUser(user: User, done: TDone) {
        done(null, {
            sub: user.id,
            email: user.email,
            role: user.role,
            permissions: user.permissions,
        });
    }

    async deserializeUser(payload: ActiveUserData, done: TDone) {
        done(null, payload);
    }
}
