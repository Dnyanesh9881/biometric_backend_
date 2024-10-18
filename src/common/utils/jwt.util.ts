// src/common/utils/jwt.util.ts
import * as jwt from 'jsonwebtoken';

export class JwtUtil {
   // Use environment variable for secret key

  static generateToken(payload: any): string {
    return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
  }

  static verifyToken(token: string): any {
    try {
      return jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      return null;
    }
  }
}
