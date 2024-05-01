import { IsNotEmpty, IsString, IsEmail } from 'class-validator';

export class forgotPasswordDto {
    @IsNotEmpty()
    @IsString()
    @IsEmail()
    public email: string;
}