import { UserRole } from '../user-role.enum';

export class VerifyResponseDto {
  id: string;
  email: string;
  username: string;
  role?: UserRole;
}
