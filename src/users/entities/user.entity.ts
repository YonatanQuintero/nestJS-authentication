import { Column, Entity, JoinTable, OneToMany, PrimaryGeneratedColumn } from "typeorm";
import { Role } from "../enums/role.enum";
import { PermissionType } from "src/iam/authorization/permission.type";
import { ApiKey } from "../api-keys/entities/api-key.entity";

@Entity()
export class User {

    @PrimaryGeneratedColumn()
    id: number;

    @Column({ unique: true })
    email: string;

    @Column({ nullable: true })
    password: string;

    @Column({ default: Role.Regular })
    role: Role;

    // NOTE: Having the "permissions" column in combination with the "role"
    // likely does not make sense. We use both in this course just to showcase
    // two different approaches to authorization.
    @Column({ type: 'json' })
    permissions: PermissionType[];

    @JoinTable()
    @OneToMany((type) => ApiKey, (apiKey) => apiKey.user)
    apiKeys: ApiKey[];

    @Column({ nullable: true })
    googleId: string;

    @Column({ default: false })
    isTfaEnabled: boolean;

    @Column({ nullable: true })
    tfaSecret: string;
}
