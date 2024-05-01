import { IsNotEmpty, IsString, Length } from 'class-validator';

export class signInDto {

    @IsNotEmpty()
    @IsString()
    public usernamme: string;

    @IsNotEmpty()
    @IsString()
    @Length(3, 20, { message: 'Passowrd has to be at between 3 and 20 chars' })
    public password: string;
}