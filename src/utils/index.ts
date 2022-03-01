import { UserRole } from 'src/auth/user-role.enum';

export const extractRolesFromAdminString = (
  adminRoleList: string,
  email: string,
) => {
  if (!adminRoleList) {
    return UserRole.USER;
  }

  const rolesAsArray: string[] = adminRoleList.split(',');
  if (rolesAsArray.includes(email)) {
    return UserRole.ADMIN;
  }

  return UserRole.USER;
};
