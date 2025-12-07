import {
  Controller,
  Post,
  Body,
  UseGuards,
  Get,
  Request,
  UnauthorizedException,
  Req,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth/auth.service';
import { CurrentIdentity } from './common/decorators/current-identity.decorator';
import { SignupDto } from './auth/dto/signup.dto';
import { LoginDto } from './auth/dto/login.dto';
import { CreateApiKeyDto } from './api-key/dto/create-api-key.dto';
import type { Identity } from './common/interfaces/identity.interface';

@Controller()
export class AppController {
  constructor(private authService: AuthService) {}

  @Post('auth/signup')
  async signup(@Body() body: SignupDto) {
    return this.authService.signup(body.email, body.password);
  }

  @Post('auth/login')
  async login(@Body() body: LoginDto) {
    return this.authService.login(body.email, body.password);
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('keys/create')
  async createKey(@Body() body: CreateApiKeyDto) {
    return this.authService.createApiKey(body.serviceName);
  }

  @UseGuards(AuthGuard(['jwt', 'api-key']))
  @Get('protected/hybrid')
  getHybridData(@CurrentIdentity() identity: Identity) {
    if (identity.type === 'service') {
      return `Hello Service: ${identity.serviceName}`;
    }
    return `Hello User: ${identity.email}`;
  }

  @UseGuards(AuthGuard('api-key'))
  @Get('protected/service-only')
  getServiceData(@CurrentIdentity() identity: Identity) {
    return {
      message: `Hello from ${identity.serviceName}`,
      serviceId: identity.serviceId,
      type: identity.type,
    };
  }

  @UseGuards(AuthGuard(['jwt', 'api-key']))
  @Post('auth/logout')
  async logout(@CurrentIdentity() identity: Identity, @Req() req: any) {
    const authHeader = req.headers['authorization'];
    const token = authHeader?.replace('Bearer ', '');

    return this.authService.logout(identity, token);
  }
}
