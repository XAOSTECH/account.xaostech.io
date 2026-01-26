/**
 * Validation schemas for account.xaostech.io
 */
import { z } from 'zod';

export const PasswordSchema = z.object({
    password: z
        .string()
        .min(8, 'Password must be at least 8 characters')
        .regex(/[A-Z]/, 'Password must contain an uppercase letter')
        .regex(/[0-9]/, 'Password must contain a number')
        .regex(/[^a-zA-Z0-9]/, 'Password must contain a special character'),
});

export const EmailSchema = z.object({
    email: z.string().email('Invalid email address'),
});

export const UsernameSchema = z.object({
    username: z
        .string()
        .min(3, 'Username must be at least 3 characters')
        .max(32, 'Username must be at most 32 characters')
        .regex(/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores, and hyphens'),
});

export const ResetPasswordSchema = z.object({
    token: z.string(),
    password: z.string().min(8),
});

export const ProfileUpdateSchema = z.object({
    username: z.string().min(3).max(32).optional(),
    display_name: z.string().max(64).optional(),
    bio: z.string().max(500).optional(),
    location: z.string().max(100).optional(),
    website: z.string().url().optional().or(z.literal('')),
});

export const ChildAccountSchema = z.object({
    username: z.string().min(3).max(32),
    display_name: z.string().max(64).optional(),
    birth_year: z.number().int().min(2000).max(new Date().getFullYear()),
    content_filter_level: z.enum(['strict', 'moderate', 'off']).default('strict'),
});

export const NotificationSettingsSchema = z.object({
    email_enabled: z.boolean().default(true),
    push_enabled: z.boolean().default(true),
    friend_requests: z.boolean().default(true),
    wall_posts: z.boolean().default(true),
    system_alerts: z.boolean().default(true),
});

export type Password = z.infer<typeof PasswordSchema>;
export type Email = z.infer<typeof EmailSchema>;
export type Username = z.infer<typeof UsernameSchema>;
export type ResetPassword = z.infer<typeof ResetPasswordSchema>;
export type ProfileUpdate = z.infer<typeof ProfileUpdateSchema>;
export type ChildAccount = z.infer<typeof ChildAccountSchema>;
export type NotificationSettings = z.infer<typeof NotificationSettingsSchema>;
