// app/api/[[...route]]/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import crypto from 'crypto';

// Configuración de la base de datos
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const JWT_SECRET = process.env.JWT_SECRET || 'bwp_platform_super_secret_key_2026';

// Email Transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_EMAIL,
    pass: process.env.GMAIL_PASSWORD,
  },
});

// Helper para verificar token JWT
async function verifyAuth(request: NextRequest) {
  const authHeader = request.headers.get('authorization');
  if (!authHeader) return null;

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { id: number, email: string };
    return decoded;
  } catch {
    return null;
  }
}

// Función para inicializar la base de datos
async function initDb() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        address TEXT,
        country VARCHAR(100),
        user_type VARCHAR(20) DEFAULT 'individual',
        company_name VARCHAR(255),
        company_location TEXT,
        company_phone VARCHAR(50),
        is_verified BOOLEAN DEFAULT FALSE,
        verification_token VARCHAR(255),
        reset_token VARCHAR(255),
        profile_image TEXT,
        api_token VARCHAR(255) UNIQUE,
        mfa_enabled BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS devices (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        type VARCHAR(50) NOT NULL,
        ip VARCHAR(50) NOT NULL,
        status VARCHAR(50) NOT NULL,
        os VARCHAR(100),
        department VARCHAR(100),
        cpu INTEGER,
        ram INTEGER,
        disk INTEGER,
        protection_active BOOLEAN DEFAULT TRUE,
        vulnerabilities TEXT[],
        policies TEXT[],
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS incidents (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        severity VARCHAR(50) NOT NULL,
        status VARCHAR(50) NOT NULL,
        target VARCHAR(255) NOT NULL,
        target_type VARCHAR(50) NOT NULL,
        department VARCHAR(100),
        timestamp VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('Database initialized');
  } catch (err) {
    console.error('Error initializing database:', err);
  } finally {
    client.release();
  }
}

// Función para seedear datos de usuario (mejorada con verificación)
async function seedUserData(userId: number) {
  const client = await pool.connect();
  try {
    // Verificar si ya tiene dispositivos
    const existingDevices = await client.query(
      'SELECT COUNT(*) FROM devices WHERE user_id = $1',
      [userId]
    );
    
    if (parseInt(existingDevices.rows[0].count) === 0) {
      const devices = [
        { name: 'SRV-PROD-SQL', type: 'Server', ip: '10.0.4.12', status: 'Online', os: 'Windows Server 2022', department: 'IT INFRASTRUCTURE', cpu: 45, ram: 72, disk: 30, vulnerabilities: ['CVE-2023-24880', 'CVE-2023-24881'], policies: ['p1', 'p2', 'p3'] },
        { name: 'CEO-LAPTOP', type: 'PC', ip: '192.168.1.45', status: 'Critical', os: 'Windows 11 Pro', department: 'ADMINISTRACIÓN', cpu: 88, ram: 92, disk: 15, vulnerabilities: ['CVE-2024-0001'], policies: ['p1', 'p2'] },
        { name: 'CAM-ENTRANCE-01', type: 'Camera', ip: '10.0.5.101', status: 'Online', os: 'BWP-OS v2.1', department: 'SEGURIDAD FÍSICA', cpu: 12, ram: 25, disk: 88, vulnerabilities: [], policies: ['p3'] },
        { name: 'GCP-NODE-01', type: 'Server', ip: '35.230.12.4', status: 'Online', os: 'Ubuntu 22.04 LTS', department: 'DATACENTER CORE', cpu: 32, ram: 45, disk: 12, vulnerabilities: ['CVE-2023-32233'], policies: ['p1', 'p3'] },
        { name: 'MARKETING-PC-01', type: 'PC', ip: '192.168.1.102', status: 'Online', os: 'Windows 10 Pro', department: 'Ventas', cpu: 22, ram: 35, disk: 45, vulnerabilities: [], policies: ['p1'] },
        { name: 'HR-MANAGER-PC', type: 'PC', ip: '192.168.1.105', status: 'Online', os: 'Windows 11 Home', department: 'Recursos Humanos', cpu: 15, ram: 40, disk: 60, vulnerabilities: [], policies: ['p1', 'p2'] },
      ];

      for (const d of devices) {
        await client.query(
          `INSERT INTO devices (user_id, name, type, ip, status, os, department, cpu, ram, disk, vulnerabilities, policies) 
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
          [userId, d.name, d.type, d.ip, d.status, d.os, d.department, d.cpu, d.ram, d.disk, d.vulnerabilities, d.policies]
        );
      }
    }

    // Verificar si ya tiene incidentes
    const existingIncidents = await client.query(
      'SELECT COUNT(*) FROM incidents WHERE user_id = $1',
      [userId]
    );

    if (parseInt(existingIncidents.rows[0].count) === 0) {
      const incidents = [
        { title: 'Infiltración Bloqueada', severity: 'Critical', status: 'Blocked', target: 'SRV-PROD-SQL', target_type: 'Server', department: 'IT INFRASTRUCTURE', timestamp: 'Hace 2 min' },
        { title: 'Vulnerabilidad CVE Detectada', severity: 'High', status: 'Pending', target: 'CEO-LAPTOP', target_type: 'PC', department: 'ADMINISTRACIÓN', timestamp: 'Hace 15 min' },
        { title: 'BWP Agent Sync Success', severity: 'Low', status: 'Monitoring', target: 'GCP-NODE-01', target_type: 'Server', department: 'DATACENTER CORE', timestamp: 'Hace 1 hora' },
      ];

      for (const i of incidents) {
        await client.query(
          `INSERT INTO incidents (user_id, title, severity, status, target, target_type, department, timestamp) 
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
          [userId, i.title, i.severity, i.status, i.target, i.target_type, i.department, i.timestamp]
        );
      }
    }
  } catch (err) {
    console.error('Error seeding user data:', err);
    // No hacer fallar el registro si el seed falla
  } finally {
    client.release();
  }
}

// Inicializar DB al arrancar
initDb();

// Manejador principal de rutas - GET
export async function GET(request: NextRequest) {
  const pathname = request.nextUrl.pathname;
  
  // Verificación de email
  if (pathname.match(/\/api\/auth\/verify\/.+/)) {
    const token = pathname.split('/').pop();
    try {
      const result = await pool.query(
        'UPDATE users SET is_verified = TRUE, verification_token = NULL WHERE verification_token = $1 RETURNING *',
        [token]
      );

      if (result.rows.length === 0) {
        return NextResponse.json({ 
          success: false, 
          message: 'Token inválido o cuenta ya verificada.' 
        }, { status: 400 });
      }

      return NextResponse.json({ 
        success: true, 
        message: 'Cuenta verificada exitosamente. Ya puedes iniciar sesión.' 
      });
    } catch (err) {
      console.error('Verification error:', err);
      return NextResponse.json({ 
        success: false, 
        message: 'Error al procesar la verificación.' 
      }, { status: 500 });
    }
  }

  // Dispositivos
  if (pathname === '/api/devices') {
    const user = await verifyAuth(request);
    if (!user) {
      return NextResponse.json({ 
        success: false, 
        message: 'No autorizado' 
      }, { status: 401 });
    }

    try {
      const result = await pool.query(
        'SELECT * FROM devices WHERE user_id = $1 ORDER BY created_at DESC', 
        [user.id]
      );
      return NextResponse.json(result.rows);
    } catch (err) {
      return NextResponse.json({ 
        success: false, 
        message: 'Error al obtener dispositivos' 
      }, { status: 500 });
    }
  }

  // Incidentes
  if (pathname === '/api/incidents') {
    const user = await verifyAuth(request);
    if (!user) {
      return NextResponse.json({ 
        success: false, 
        message: 'No autorizado' 
      }, { status: 401 });
    }

    try {
      const result = await pool.query(
        'SELECT * FROM incidents WHERE user_id = $1 ORDER BY created_at DESC', 
        [user.id]
      );
      return NextResponse.json(result.rows);
    } catch (err) {
      return NextResponse.json({ 
        success: false, 
        message: 'Error al obtener incidentes' 
      }, { status: 500 });
    }
  }

  return NextResponse.json({ 
    success: false, 
    message: 'Ruta no encontrada' 
  }, { status: 404 });
}

// Manejador principal de rutas - POST
export async function POST(request: NextRequest) {
  const pathname = request.nextUrl.pathname;
  const body = await request.json();

  // Registro
  if (pathname === '/api/auth/register') {
    const { 
      name, email, password, address, country, 
      userType, companyName, companyLocation, companyPhone 
    } = body;

    try {
      // Validar campos requeridos
      if (!name || !email || !password) {
        return NextResponse.json({ 
          success: false, 
          message: 'Todos los campos son requeridos.' 
        }, { status: 400 });
      }

      const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
      if (userExists.rows.length > 0) {
        return NextResponse.json({ 
          success: false, 
          message: 'El correo ya está registrado.' 
        }, { status: 400 });
      }

      if (userType === 'company') {
        const publicDomains = ['gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'icloud.com'];
        const domain = email.split('@')[1];
        if (publicDomains.includes(domain)) {
          return NextResponse.json({ 
            success: false, 
            message: 'Las empresas deben usar correos corporativos.' 
          }, { status: 400 });
        }
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const verificationToken = crypto.randomBytes(32).toString('hex');
      const apiToken = 'BWP-' + Math.random().toString(36).substr(2, 9).toUpperCase();

      const newUser = await pool.query(
        `INSERT INTO users 
        (name, email, password, address, country, user_type, company_name, company_location, company_phone, verification_token, api_token) 
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id, name, email`,
        [name, email, hashedPassword, address, country, userType, companyName, companyLocation, companyPhone, verificationToken, apiToken]
      );

      const userId = newUser.rows[0].id;
      
      // Intentar seedear datos pero no fallar si hay error
      try {
        await seedUserData(userId);
      } catch (seedErr) {
        console.error('Seed error (non-critical):', seedErr);
      }

      // Enviar email de verificación
      const verificationUrl = `${process.env.APP_URL || 'http://localhost:3000'}/verify?token=${verificationToken}`;
      
      try {
        await transporter.sendMail({
          from: `"BWP Security" <${process.env.GMAIL_EMAIL}>`,
          to: email,
          subject: 'Verifica tu cuenta BWP Platform',
          html: `
            <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: auto; border: 1px solid #eee; padding: 40px; border-radius: 10px;">
              <h2 style="color: #8B1E1E; text-align: center;">Bienvenido a BWP Platform</h2>
              <p>Hola <strong>${name}</strong>,</p>
              <p>Gracias por registrarte en nuestra plataforma de ciberseguridad. Para activar tu cuenta, por favor haz clic en el siguiente enlace:</p>
              <div style="text-align: center; margin: 30px 0;">
                <a href="${verificationUrl}" style="background-color: #8B1E1E; color: white; padding: 15px 25px; text-decoration: none; border-radius: 5px; font-weight: bold;">VERIFICAR MI CUENTA</a>
              </div>
              <p style="font-size: 12px; color: #666;">Si no creaste esta cuenta, puedes ignorar este correo.</p>
              <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
              <p style="text-align: center; font-size: 10px; color: #999;">&copy; 2026 BWP Cybersecurity Protection Platform</p>
            </div>
          `,
        });
      } catch (emailErr) {
        console.error('Email error (non-critical):', emailErr);
        // No fallar el registro si el email no se envía
      }

      return NextResponse.json({ 
        success: true, 
        message: 'Registro exitoso. Revisa tu correo para verificar tu cuenta.' 
      }, { status: 201 });
      
    } catch (err) {
      console.error('Register error:', err);
      return NextResponse.json({ 
        success: false, 
        message: 'Error en el servidor.' 
      }, { status: 500 });
    }
  }

  // Login
  if (pathname === '/api/auth/login') {
    const { email, password } = body;
    
    try {
      if (!email || !password) {
        return NextResponse.json({ 
          success: false, 
          message: 'Email y contraseña son requeridos.' 
        }, { status: 400 });
      }

      const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
      
      if (result.rows.length === 0) {
        return NextResponse.json({ 
          success: false, 
          message: 'Credenciales inválidas.' 
        }, { status: 400 });
      }

      const user = result.rows[0];
      
      if (!user.is_verified) {
        return NextResponse.json({ 
          success: false, 
          message: 'Por favor verifica tu correo antes de entrar.' 
        }, { status: 401 });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return NextResponse.json({ 
          success: false, 
          message: 'Credenciales inválidas.' 
        }, { status: 400 });
      }

      const token = jwt.sign(
        { id: user.id, email: user.email }, 
        JWT_SECRET, 
        { expiresIn: '7d' }
      );
      
      // Eliminar datos sensibles
      delete user.password;
      delete user.verification_token;
      delete user.reset_token;
      delete user.api_token;
      
      return NextResponse.json({ 
        success: true,
        token, 
        user 
      });

    } catch (err) {
      console.error('Login error:', err);
      return NextResponse.json({ 
        success: false, 
        message: 'Error en el servidor.' 
      }, { status: 500 });
    }
  }

  // Forgot Password
  if (pathname === '/api/auth/forgot-password') {
    const { email } = body;
    
    try {
      if (!email) {
        return NextResponse.json({ 
          success: false, 
          message: 'Email es requerido.' 
        }, { status: 400 });
      }

      const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
      
      if (result.rows.length === 0) {
        // Por seguridad, no revelar si el email existe
        return NextResponse.json({ 
          success: true, 
          message: 'Si el correo existe, recibirás un enlace de recuperación.' 
        });
      }

      const resetToken = crypto.randomBytes(32).toString('hex');
      await pool.query(
        'UPDATE users SET reset_token = $1 WHERE email = $2', 
        [resetToken, email]
      );

      const resetUrl = `${process.env.APP_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}`;

      try {
        await transporter.sendMail({
          from: `"BWP Security" <${process.env.GMAIL_EMAIL}>`,
          to: email,
          subject: 'Recupera tu contraseña - BWP Platform',
          html: `
            <div style="font-family: 'Inter', sans-serif; max-width: 600px; margin: auto; border: 1px solid #eee; padding: 40px; border-radius: 10px;">
              <h2 style="color: #8B1E1E; text-align: center;">Recuperación de Contraseña</h2>
              <p>Has solicitado restablecer tu contraseña. Haz clic en el siguiente enlace:</p>
              <div style="text-align: center; margin: 30px 0;">
                <a href="${resetUrl}" style="background-color: #8B1E1E; color: white; padding: 15px 25px; text-decoration: none; border-radius: 5px; font-weight: bold;">RESTABLECER CONTRASEÑA</a>
              </div>
              <p style="font-size: 12px; color: #666;">Este enlace expirará en 1 hora.</p>
            </div>
          `,
        });
      } catch (emailErr) {
        console.error('Reset email error:', emailErr);
      }

      return NextResponse.json({ 
        success: true, 
        message: 'Si el correo existe, recibirás un enlace de recuperación.' 
      });

    } catch (err) {
      console.error('Forgot password error:', err);
      return NextResponse.json({ 
        success: false, 
        message: 'Error en el servidor.' 
      }, { status: 500 });
    }
  }

  // Reset Password
  if (pathname === '/api/auth/reset-password') {
    const { token, newPassword } = body;
    
    try {
      if (!token || !newPassword) {
        return NextResponse.json({ 
          success: false, 
          message: 'Token y nueva contraseña son requeridos.' 
        }, { status: 400 });
      }

      if (newPassword.length < 6) {
        return NextResponse.json({ 
          success: false, 
          message: 'La contraseña debe tener al menos 6 caracteres.' 
        }, { status: 400 });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      
      const result = await pool.query(
        'UPDATE users SET password = $1, reset_token = NULL WHERE reset_token = $2 RETURNING id',
        [hashedPassword, token]
      );

      if (result.rows.length === 0) {
        return NextResponse.json({ 
          success: false, 
          message: 'Token inválido o expirado.' 
        }, { status: 400 });
      }

      return NextResponse.json({ 
        success: true, 
        message: 'Contraseña actualizada correctamente.' 
      });

    } catch (err) {
      console.error('Reset password error:', err);
      return NextResponse.json({ 
        success: false, 
        message: 'Error en el servidor.' 
      }, { status: 500 });
    }
  }

  return NextResponse.json({ 
    success: false, 
    message: 'Ruta no encontrada' 
  }, { status: 404 });
}

// Manejador principal de rutas - PUT
export async function PUT(request: NextRequest) {
  const pathname = request.nextUrl.pathname;

  // Update Profile
  if (pathname === '/api/user/profile') {
    const user = await verifyAuth(request);
    if (!user) {
      return NextResponse.json({ 
        success: false, 
        message: 'No autorizado' 
      }, { status: 401 });
    }

    const body = await request.json();
    const { name, address, profileImage, mfaEnabled } = body;

    try {
      const result = await pool.query(
        'UPDATE users SET name = $1, address = $2, profile_image = $3, mfa_enabled = $4 WHERE id = $5 RETURNING *',
        [name || null, address || null, profileImage || null, mfaEnabled || false, user.id]
      );

      const updatedUser = result.rows[0];
      delete updatedUser.password;
      delete updatedUser.verification_token;
      delete updatedUser.reset_token;
      delete updatedUser.api_token;
      
      return NextResponse.json(updatedUser);

    } catch (err) {
      console.error('Update profile error:', err);
      return NextResponse.json({ 
        success: false, 
        message: 'Error al actualizar perfil' 
      }, { status: 500 });
    }
  }

  return NextResponse.json({ 
    success: false, 
    message: 'Ruta no encontrada' 
  }, { status: 404 });
}

// Manejador principal de rutas - DELETE
export async function DELETE(request: NextRequest) {
  const pathname = request.nextUrl.pathname;

  // Eliminar dispositivo
  if (pathname.match(/\/api\/devices\/\d+/)) {
    const user = await verifyAuth(request);
    if (!user) {
      return NextResponse.json({ 
        success: false, 
        message: 'No autorizado' 
      }, { status: 401 });
    }

    const id = pathname.split('/').pop();
    
    try {
      const result = await pool.query(
        'DELETE FROM devices WHERE id = $1 AND user_id = $2 RETURNING id',
        [id, user.id]
      );

      if (result.rows.length === 0) {
        return NextResponse.json({ 
          success: false, 
          message: 'Dispositivo no encontrado' 
        }, { status: 404 });
      }

      return NextResponse.json({ 
        success: true, 
        message: 'Dispositivo eliminado correctamente' 
      });

    } catch (err) {
      console.error('Delete device error:', err);
      return NextResponse.json({ 
        success: false, 
        message: 'Error al eliminar dispositivo' 
      }, { status: 500 });
    }
  }

  return NextResponse.json({ 
    success: false, 
    message: 'Ruta no encontrada' 
  }, { status: 404 });
}