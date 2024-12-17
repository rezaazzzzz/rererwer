import { Controller, Get, Post, Body, UseGuards, HttpException } from '@nestjs/common';
import { UserService } from './user.service';
import { RolesGuard } from './gaurd/user.gaurd';  
import { Roles } from './roles'; 
import { UserRole } from './user.role.enum';

@Controller('user')
export class UserController {
  constructor(private userService: UserService) {}

  @Post('login')
  async loginUser(@Body() user: { username: string; password: string }) {
    return await this.userService.loginUser(user);
  }

  @Post('create')
  async createUser(@Body() user: { username: string; password: string }) {
    return await this.userService.createUser(user);
  }

  @Post('request-password-reset')
  async requestPasswordReset(@Body() { username }: { username: string }) {
    return await this.userService.requestPasswordReset(username);
  }

  @Post('admin/approve-password-reset')
  @Roles(UserRole.ADMIN)  
  @UseGuards(RolesGuard)
  async approvePasswordReset(
    @Body() { requestId, newPassword }: { requestId: string, newPassword: string }
  ) {
    return await this.userService.approvePasswordReset(requestId, newPassword);
  }

  @Get('admin/password-reset-requests')
  @Roles(UserRole.ADMIN)  
  @UseGuards(RolesGuard)
  async getPasswordResetRequests() {
    return await this.userService.getPasswordResetRequests();
  }
}
