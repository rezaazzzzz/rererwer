import { IsString, IsNotEmpty, IsOptional, IsEnum } from 'class-validator';
import { UserRole } from './../user.role.enum'; 

export class User {
  @IsString()
  @IsNotEmpty()
  username: string;

  @IsString()
  @IsNotEmpty()
  password: string;

  @IsEnum(UserRole) 
  @IsOptional()
  role?: UserRole = UserRole.USER; 
}
