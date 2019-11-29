import { Repository, EntityRepository } from 'typeorm';
import { User } from './user.entity';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { ConflictException, InternalServerErrorException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
@EntityRepository(User)
export class UserRepository extends Repository<User> {

  async signUp(authCredentialsDto: AuthCredentialsDto): Promise<void> {
    const { username, password } = authCredentialsDto;

    const user = new User();
    user.username = username;
    user.password = await this.passwordHash(password);

    try {
      await user.save();
    } catch (error) {
      if (error.code === '23505') {
        throw new ConflictException('username already exist');
      }

      throw new InternalServerErrorException();
    }
  }

 async validateUserPassword(authCredentialsDto: AuthCredentialsDto): Promise<string> {
   const { username, password } = authCredentialsDto;
   const user = await this.findOne({ username });

   if (user && await user.validatePassword(password)) {
     return user.username;
   }

   return null;

 }

  private async passwordHash(password: string): Promise<string> {
    const salt = await bcrypt.genSalt(12);

    return bcrypt.hash(password, salt);
  }
}
