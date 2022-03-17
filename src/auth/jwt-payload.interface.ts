import { UserRole } from './user-role.enum';

export interface JwtPayload {
  id: string;
  email: string;
  role: UserRole;
  username: string;
}
