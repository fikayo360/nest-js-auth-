import { IsNotEmpty, IsNumber, IsString, Length} from 'class-validator';

export class refreshToken {

    @IsNotEmpty()
    @IsNumber()
    public userId: number;

    @IsNotEmpty()
    @IsString()
    public rt: string;
}