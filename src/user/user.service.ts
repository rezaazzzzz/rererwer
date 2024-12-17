import { HttpException, Injectable } from '@nestjs/common';
import Redis from 'ioredis';
import { User } from './entities/user.entity';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { UserRole } from './user.role.enum';

@Injectable()
export class UserService {
  private redis: Redis;
  private jwtService: JwtService;

  constructor(jwtService: JwtService) {
    this.redis = new Redis({
      host: 'localhost',
      port: 6379,
      password: null,
    });
    this.jwtService = jwtService;
  }

  async findUserByUsername(username: string): Promise<User | null> {
    const userIds = await this.redis.smembers('users');

    for (const userId of userIds) {
      const userData = await this.redis.get(`user:${userId}`);
      if (userData) {
        const user = JSON.parse(userData);
        if (user.username === username) {
          return user;
        }
      }
    }

    return null;
  }

  async loginUser(user: User): Promise<{ token: string; role: string }> {
    const { username, password } = user;

    const storedUser = await this.findUserByUsername(username);
    if (!storedUser) {
      throw new HttpException('User not found', 404);
    }

    const isPasswordValid = await bcrypt.compare(password, storedUser.password);
    if (!isPasswordValid) {
      throw new HttpException('Invalid password', 401);
    }

    const payload = { username, role: storedUser.role };
    const token = this.jwtService.sign(payload);

    return { token, role: storedUser.role };
  }

  async createUser(user: User): Promise<void> {
    const { username, password, role } = user;

    const existUser = await this.findUserByUsername(username);
    if (existUser) {
      throw new HttpException('User already exists', 404);
    }

    if (!username || !password) {
      throw new HttpException('Username and password are required', 400);
    }

    const userRole = role || UserRole.USER;

    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);
    const hashedPassword = await bcrypt.hash(password, salt);

    const userId = Date.now();
    await this.redis.set(
      `user:${userId}`,
      JSON.stringify({ username, password: hashedPassword, role: userRole }),
    );

    await this.redis.sadd('users', userId.toString());
  }

  async requestPasswordReset(username: string): Promise<string> {
    const user = await this.findUserByUsername(username);
    if (!user) {
      throw new HttpException('User not found', 404);
    }

    const requestId = `reset-request:${Date.now()}`;
    await this.redis.set(requestId, JSON.stringify({ username, status: 'pending' }));

    return `Password reset request submitted for username '${username}'`;
  }

  async getPasswordResetRequests(): Promise<any[]> {
    const keys = await this.redis.keys('reset-request:*');
    const requests = [];

    for (const key of keys) {
      const requestData = await this.redis.get(key);
      if (requestData) {
        requests.push({ id: key, ...JSON.parse(requestData) });
      }
    }

    return requests;
  }

  async approvePasswordReset(requestId: string, newPassword: string): Promise<string> {
    const requestData = await this.redis.get(requestId);
    if (!requestData) {
      throw new HttpException('Reset request not found', 404);
    }

    const { username } = JSON.parse(requestData);

    const userIds = await this.redis.smembers('users');
    for (const userId of userIds) {
      const userData = await this.redis.get(`user:${userId}`);
      if (userData) {
        const user = JSON.parse(userData);
        if (user.username === username) {
          const saltRounds = 10;
          const salt = await bcrypt.genSalt(saltRounds);
          const hashedPassword = await bcrypt.hash(newPassword, salt);

          await this.redis.set(
            `user:${userId}`,
            JSON.stringify({ ...user, password: hashedPassword }),
          );

          await this.redis.del(requestId);

          return `Password reset for '${username}' successfully approved`;
        }
      }
    }

    throw new HttpException('User not found', 404);
  }
}
