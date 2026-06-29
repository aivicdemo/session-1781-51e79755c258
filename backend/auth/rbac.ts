import { APIGatewayProxyEvent } from 'aws-lambda';

export type Role = 'admin' | 'operator' | 'viewer';

export interface AuthContext {
  userId: string;
  role: Role;
  organizationId: string;
}

export function extractAuthContext(event: APIGatewayProxyEvent): AuthContext {
  const authHeader = event.headers['Authorization'] || '';
  const token = authHeader.replace('Bearer ', '');
  
  try {
    const decoded = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    return {
      userId: decoded.userId,
      role: decoded.role as Role,
      organizationId: decoded.organizationId,
    };
  } catch (e) {
    throw new Error('Invalid token');
  }
}

export function requireRole(allowedRoles: Role[]): (context: AuthContext) => boolean {
  return (context: AuthContext) => allowedRoles.includes(context.role);
}

export const rolePermissions: Record<Role, Set<string>> = {
  admin: new Set([
    'users:read',
    'users:create',
    'users:update',
    'users:delete',
    'salesData:read',
    'salesData:create',
    'salesData:update',
    'salesData:delete',
    'validationRules:read',
    'validationRules:create',
    'validationRules:update',
    'validationRules:delete',
    'validationErrors:read',
    'validationErrors:update',
    'billing:read',
    'billing:create',
    'billing:update',
    'billing:delete',
    'customers:read',
    'customers:create',
    'customers:update',
    'customers:delete',
    'services:read',
    'services:create',
    'services:update',
    'services:delete',
    'bulk:import',
    'audit:read',
  ]),
  operator: new Set([
    'users:read',
    'salesData:read',
    'salesData:create',
    'salesData:update',
    'validationRules:read',
    'validationErrors:read',
    'validationErrors:update',
    'billing:read',
    'billing:create',
    'billing:update',
    'customers:read',
    'customers:create',
    'customers:update',
    'services:read',
    'bulk:import',
    'audit:read',
  ]),
  viewer: new Set([
    'users:read',
    'salesData:read',
    'validationRules:read',
    'validationErrors:read',
    'billing:read',
    'customers:read',
    'services:read',
    'audit:read',
  ]),
};

export function hasPermission(context: AuthContext, permission: string): boolean {
  return rolePermissions[context.role].has(permission);
}

export function checkPermission(context: AuthContext, permission: string): void {
  if (!hasPermission(context, permission)) {
    throw new Error(`Forbidden: ${permission}`);
  }
}